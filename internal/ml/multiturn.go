// SPDX-License-Identifier: Apache-2.0
// Provenance: github.com/aegisgatesecurity/aegisgate-platform/pkg/ml/multiturn.go
// =========================================================================
// AegisGate Rampart - Multi-Turn Attack Detection
// =========================================================================
//
// Multi-turn attacks unfold across multiple conversation turns, where each
// individual message may appear benign but the cumulative effect is malicious.
// This detector tracks per-conversation risk state, applies attack chain
// patterns, and accumulates suspicion scores to detect gradual escalation.
//
// Additionally, this detector tracks BENIGN conversation context (customer
// support, medical, legal, HR, financial) for PII false positive suppression.
// When the conversation context is clearly legitimate and all detections are
// PII-only, the proxy gatekeeper can suppress the false positive.
//
// Ported from Platform's pkg/ml/multiturn.go with simplifications for
// Rampart's architecture (no ATLAS, no CombinedDetector sub-detectors).
// =========================================================================

package ml

import (
	"crypto/sha256"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// ============================================================================
// Types
// ============================================================================

// MultiTurnConfig holds configuration for the multi-turn detector.
type MultiTurnConfig struct {
	MaxSessions int
	SessionTTL  time.Duration

	BlockThreshold float64
	AlertThreshold float64

	EscalationMultiplier float64
	RepetitionPenalty    float64
	DecayRate            float64

	EnableLogging bool

	// Context tracking configuration
	ContextSuppressThreshold float64
	ContextMinTurns          int
	ContextDecayRate         float64
}

// TurnSignals holds the detection signals from a single turn.
type TurnSignals struct {
	DetectionCount    int
	HighSeverityCount int
	CriticalCount     int
	MLScore           float64
	ContentLength     int
	Role              string
	MatchedPatterns   []string
	Categories        []string
}

// SessionState holds the cumulative detection state for a conversation.
type SessionState struct {
	ConversationID  string
	TurnCount       int
	CumulativeScore float64
	TurnScores      []float64
	MatchedChains   []string
	PatternHistory  map[string]int
	LastActivity    time.Time
	CreatedAt       time.Time
	BlockedAt       time.Time
	LastTurnSignals TurnSignals
	Context         *ConversationContext
}

// MultiTurnResult is returned by Analyze() with the detection decision.
type MultiTurnResult struct {
	SessionID          string
	TurnNumber         int
	TurnScore          float64
	CumulativeScore    float64
	ShouldBlock        bool
	ShouldAlert        bool
	MatchedChains      []string
	EscalationDetected bool
	RepetitionDetected bool
	NewPatterns        []string
	DecayApplied       float64
	ChainDetails       []string
	BenignContext      *ConversationContext
}

// ============================================================================
// Session Store
// ============================================================================

type sessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*SessionState
	maxSize  int
	ttl      time.Duration
}

func newSessionStore(maxSize int, ttl time.Duration) *sessionStore {
	if maxSize <= 0 {
		maxSize = 10000
	}
	if ttl <= 0 {
		ttl = 30 * time.Minute
	}
	return &sessionStore{
		sessions: make(map[string]*SessionState),
		maxSize:  maxSize,
		ttl:      ttl,
	}
}

func (s *sessionStore) Get(id string) *SessionState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	session, ok := s.sessions[id]
	if !ok {
		return nil
	}
	if time.Since(session.LastActivity) > s.ttl {
		return nil
	}
	return session
}

func (s *sessionStore) GetOrCreate(id string) *SessionState {
	s.mu.Lock()
	defer s.mu.Unlock()
	if session, ok := s.sessions[id]; ok {
		if time.Since(session.LastActivity) <= s.ttl {
			return session
		}
		delete(s.sessions, id)
	}
	if len(s.sessions) >= s.maxSize {
		s.evictOldest()
	}
	session := &SessionState{
		ConversationID: id,
		TurnScores:     make([]float64, 0, 10),
		MatchedChains:  make([]string, 0),
		PatternHistory: make(map[string]int),
		LastActivity:   time.Now(),
		CreatedAt:      time.Now(),
	}
	s.sessions[id] = session
	return session
}

func (s *sessionStore) Update(session *SessionState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	session.LastActivity = time.Now()
	s.sessions[session.ConversationID] = session
}

func (s *sessionStore) Delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
}

func (s *sessionStore) ActiveCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	count := 0
	now := time.Now()
	for _, session := range s.sessions {
		if now.Sub(session.LastActivity) <= s.ttl {
			count++
		}
	}
	return count
}

func (s *sessionStore) EvictExpired() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	evicted := 0
	for id, session := range s.sessions {
		if now.Sub(session.LastActivity) > s.ttl {
			delete(s.sessions, id)
			evicted++
		}
	}
	return evicted
}

func (s *sessionStore) evictOldest() {
	var oldestID string
	var oldestTime time.Time
	for id, session := range s.sessions {
		if oldestID == "" || session.LastActivity.Before(oldestTime) {
			oldestID = id
			oldestTime = session.LastActivity
		}
	}
	if oldestID != "" {
		delete(s.sessions, oldestID)
	}
}

// ============================================================================
// Multi-Turn Detector
// ============================================================================

type MultiTurnDetector struct {
	config          MultiTurnConfig
	store           *sessionStore
	contextPatterns []BenignContextPattern
	mu              sync.RWMutex
}

func NewMultiTurnDetector(config MultiTurnConfig) *MultiTurnDetector {
	if config.MaxSessions <= 0 {
		config.MaxSessions = 10000
	}
	if config.SessionTTL <= 0 {
		config.SessionTTL = 30 * time.Minute
	}
	if config.BlockThreshold <= 0 {
		config.BlockThreshold = 75.0
	}
	if config.AlertThreshold <= 0 {
		config.AlertThreshold = 40.0
	}
	if config.EscalationMultiplier <= 0 {
		config.EscalationMultiplier = 1.5
	}
	if config.RepetitionPenalty <= 0 {
		config.RepetitionPenalty = 10.0
	}
	if config.DecayRate <= 0 {
		config.DecayRate = 0.15
	}
	if config.ContextSuppressThreshold <= 0 {
		config.ContextSuppressThreshold = 25.0
	}
	if config.ContextMinTurns <= 0 {
		config.ContextMinTurns = 1
	}
	if config.ContextDecayRate <= 0 {
		config.ContextDecayRate = 0.10
	}

	return &MultiTurnDetector{
		config:          config,
		store:           newSessionStore(config.MaxSessions, config.SessionTTL),
		contextPatterns: DefaultContextPatterns(),
	}
}

// Analyze processes a single turn within a conversation.
func (d *MultiTurnDetector) Analyze(conversationID string, role string, content string, signals TurnSignals) *MultiTurnResult {
	sessionID := hashConvID(conversationID)
	session := d.store.GetOrCreate(sessionID)

	d.mu.Lock()
	defer d.mu.Unlock()

	// Apply decay for benign turns
	decayAmount := 0.0
	if session.TurnCount > 0 {
		turnScore := d.calculateTurnScore(signals)
		if turnScore == 0 {
			decayAmount = session.CumulativeScore * d.config.DecayRate
			session.CumulativeScore -= decayAmount
			if session.CumulativeScore < 0 {
				session.CumulativeScore = 0
			}
		}
	}

	turnScore := d.calculateTurnScore(signals)
	escalationDetected := d.detectEscalation(session, turnScore)
	repetitionDetected, newPatterns := d.detectRepetition(session, signals)

	// Calculate total turn contribution
	escalationBonus := 0.0
	if escalationDetected {
		escalationBonus = turnScore * (d.config.EscalationMultiplier - 1.0)
	}
	repetitionBonus := 0.0
	if repetitionDetected {
		repetitionBonus = d.config.RepetitionPenalty
	}
	totalTurnContribution := turnScore + escalationBonus + repetitionBonus

	// Update session state
	session.TurnCount++
	session.TurnScores = append(session.TurnScores, totalTurnContribution)
	session.CumulativeScore += totalTurnContribution
	session.LastTurnSignals = signals
	if session.CumulativeScore > 200 {
		session.CumulativeScore = 200
	}

	// Detect benign conversation context
	var benignContext *ConversationContext
	if len(d.contextPatterns) > 0 {
		benignContext = d.detectContext(content, session)
		session.Context = benignContext
	}

	d.store.Update(session)

	shouldBlock := session.CumulativeScore >= d.config.BlockThreshold
	shouldAlert := session.CumulativeScore >= d.config.AlertThreshold

	result := &MultiTurnResult{
		SessionID:          sessionID,
		TurnNumber:         session.TurnCount,
		TurnScore:          totalTurnContribution,
		CumulativeScore:    session.CumulativeScore,
		ShouldBlock:        shouldBlock,
		ShouldAlert:        shouldAlert,
		EscalationDetected: escalationDetected,
		RepetitionDetected: repetitionDetected,
		NewPatterns:        newPatterns,
		DecayApplied:       decayAmount,
		BenignContext:      benignContext,
	}

	if d.config.EnableLogging {
		d.logResult(result, content)
	}

	if shouldBlock && session.BlockedAt.IsZero() {
		session.BlockedAt = time.Now()
	}

	return result
}

// CheckContextStandalone runs context patterns on content without modifying
// session state. Used by the proxy for early gatekeeper checks.
func (d *MultiTurnDetector) CheckContextStandalone(content string) *ConversationContext {
	if len(d.contextPatterns) == 0 {
		return nil
	}

	ctx := &ConversationContext{
		Profile:       ContextUnknown,
		ProfileScores: make(map[ContextProfile]float64),
	}

	matchedKeywords := []string{}
	for _, pattern := range d.contextPatterns {
		if pattern.Regex.MatchString(content) {
			ctx.ProfileScores[pattern.Profile] += pattern.Weight
			matchedKeywords = append(matchedKeywords, pattern.Name)
		}
	}

	var dominantProfile ContextProfile = ContextUnknown
	var dominantScore float64
	for profile, score := range ctx.ProfileScores {
		if score > dominantScore {
			dominantProfile = profile
			dominantScore = score
		}
	}

	threshold := d.config.ContextSuppressThreshold
	if threshold <= 0 {
		threshold = 25.0
	}
	minTurns := d.config.ContextMinTurns
	if minTurns <= 0 {
		minTurns = 1
	}

	ctx.Profile = dominantProfile
	ctx.BenignScore = dominantScore
	ctx.ContextTurns = 1
	ctx.DetectedKeywords = matchedKeywords
	ctx.IsEstablished = ctx.BenignScore >= threshold && 1 >= minTurns
	ctx.LastUpdate = time.Now()

	return ctx
}

// GetSessionContext returns accumulated context from previous turns.
func (d *MultiTurnDetector) GetSessionContext(conversationID string) *ConversationContext {
	sessionID := hashConvID(conversationID)
	session := d.store.Get(sessionID)
	if session == nil || session.Context == nil {
		return nil
	}
	return session.Context
}

// GetSession returns the session state for a conversation.
func (d *MultiTurnDetector) GetSession(conversationID string) *SessionState {
	return d.store.Get(hashConvID(conversationID))
}

// ResetSession clears the session state for a conversation.
func (d *MultiTurnDetector) ResetSession(conversationID string) {
	d.store.Delete(hashConvID(conversationID))
}

// GetStats returns detection statistics.
func (d *MultiTurnDetector) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"active_sessions": d.store.ActiveCount(),
	}
}

// ============================================================================
// Internal Methods
// ============================================================================

func (d *MultiTurnDetector) calculateTurnScore(signals TurnSignals) float64 {
	// Base score from detection count and severity
	score := float64(signals.DetectionCount)*2.0 +
		float64(signals.HighSeverityCount)*5.0 +
		float64(signals.CriticalCount)*8.0

	// ML score contribution (0-1 → 0-20)
	if signals.MLScore > 0 {
		score += signals.MLScore * 20.0
	}

	return score
}

func (d *MultiTurnDetector) detectEscalation(session *SessionState, currentScore float64) bool {
	if session.TurnCount < 2 {
		return false
	}
	prevScore := session.TurnScores[len(session.TurnScores)-1]
	if currentScore > 0 && prevScore > 0 && currentScore > prevScore*2 {
		return true
	}
	if len(session.TurnScores) >= 3 {
		last3 := session.TurnScores[len(session.TurnScores)-3:]
		if last3[0] < last3[1] && last3[1] < last3[2] && last3[2] < currentScore {
			return true
		}
	}
	return false
}

func (d *MultiTurnDetector) detectRepetition(session *SessionState, signals TurnSignals) (bool, []string) {
	var newPatterns []string
	repetitionDetected := false

	for _, pattern := range signals.MatchedPatterns {
		count, exists := session.PatternHistory[pattern]
		if exists && count >= 2 {
			repetitionDetected = true
		}
		if !exists {
			newPatterns = append(newPatterns, pattern)
		}
		session.PatternHistory[pattern]++
	}

	return repetitionDetected, newPatterns
}

func (d *MultiTurnDetector) detectContext(content string, session *SessionState) *ConversationContext {
	ctx := session.Context
	if ctx == nil {
		ctx = &ConversationContext{
			Profile:       ContextUnknown,
			ProfileScores: make(map[ContextProfile]float64),
		}
	}

	// Apply decay
	decay := d.config.ContextDecayRate
	if decay <= 0 {
		decay = 0.10
	}
	for profile := range ctx.ProfileScores {
		ctx.ProfileScores[profile] *= (1.0 - decay)
		if ctx.ProfileScores[profile] < 0.5 {
			delete(ctx.ProfileScores, profile)
		}
	}

	// Scan content for context patterns
	matchedKeywords := []string{}
	turnHadSignals := false

	for _, pattern := range d.contextPatterns {
		if pattern.Regex.MatchString(content) {
			ctx.ProfileScores[pattern.Profile] += pattern.Weight
			matchedKeywords = append(matchedKeywords, pattern.Name)
			turnHadSignals = true
		}
	}

	if turnHadSignals {
		ctx.ContextTurns++
	}

	// Determine dominant profile
	var dominantProfile ContextProfile = ContextUnknown
	var dominantScore float64
	for profile, score := range ctx.ProfileScores {
		if score > dominantScore {
			dominantProfile = profile
			dominantScore = score
		}
	}

	ctx.Profile = dominantProfile
	ctx.BenignScore = dominantScore
	ctx.DetectedKeywords = matchedKeywords
	ctx.LastUpdate = time.Now()

	minTurns := d.config.ContextMinTurns
	if minTurns <= 0 {
		minTurns = 1
	}
	threshold := d.config.ContextSuppressThreshold
	if threshold <= 0 {
		threshold = 25.0
	}
	ctx.IsEstablished = ctx.BenignScore >= threshold && ctx.ContextTurns >= minTurns

	return ctx
}

func (d *MultiTurnDetector) logResult(result *MultiTurnResult, content string) {
	contentPreview := content
	if len(contentPreview) > 200 {
		contentPreview = contentPreview[:200] + "..."
	}

	attrs := []any{
		"session_id", result.SessionID,
		"turn", result.TurnNumber,
		"turn_score", fmt.Sprintf("%.1f", result.TurnScore),
		"cumulative_score", fmt.Sprintf("%.1f", result.CumulativeScore),
	}

	if result.BenignContext != nil && result.BenignContext.Profile != ContextUnknown {
		attrs = append(attrs, "context", result.BenignContext.String())
		if result.BenignContext.IsEstablished {
			attrs = append(attrs, "context_suppress", true)
		}
	}

	if result.ShouldBlock {
		slog.Error("Multi-turn attack: block threshold exceeded", attrs...)
	} else if result.ShouldAlert {
		slog.Warn("Multi-turn attack: alert threshold exceeded", attrs...)
	} else if result.TurnScore > 0 {
		slog.Info("Multi-turn detection: turn scored", attrs...)
	}
}

func hashConvID(id string) string {
	h := sha256.Sum256([]byte(id))
	return fmt.Sprintf("%x", h[:16])
}
