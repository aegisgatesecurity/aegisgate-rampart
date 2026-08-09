# What the 95% Actually Needs

**Date:** 2026-08-08  
**Analysis:** SMB/Developer vs. Enterprise Feature Segmentation  
**Goal:** Focus development on what drives 95% of adoption

---

## Executive Summary

**The 95% (SMB, developers, mid-market) needs:**
1. ✅ **Easy installation** — brew, deb, rpm (DONE)
2. ✅ **Just works** — minimal config, sensible defaults (DONE)
3. ✅ **Detects violations** — PII, secrets, compliance (DONE)
4. ✅ **Blocks threats** — active prevention (DONE)
5. ✅ **Privacy-first** — no phone-home (DONE)
6. ✅ **Affordable** — $0-49/mo (DONE)
7. ✅ **Good docs** — README, examples (DONE)
8. ⚠️ **Simple alerts** — Slack/Discord webhooks (1-2 days to port)
9. ⚠️ **Basic log viewing** — search would be nice (2-3 days)
10. ✅ **Auto-updates** — notify on new version (DONE)

**The 5% (Enterprise) needs:**
1. SSO/SAML — Platform has this
2. SIEM integration — Platform has this (can port)
3. Centralized policy — Platform has this
4. Multi-tenancy — Platform has this
5. Kubernetes/Helm — Needs building (2-3 days)
6. Custom ML — Lens has pipeline
7. Batch scanning — Needs building (3-4 days)
8. Advanced search — Needs building (2-3 days)
9. Per-user quotas — Needs building (2-3 days)
10. Compliance reports — Mappings exist, reports need work

**Key Insight:** The 95% wants **self-serve, simple, affordable**. The 5% wants **integration, control, compliance**.

**Development Priority:** Serve the 95% first (volume), then upsell the 5% (revenue).

---

## The 95% Persona: "Security-Conscious Developer Sarah"

### Profile
- **Role:** Senior Developer / Tech Lead
- **Company:** 50-500 employees (SMB to mid-market)
- **Industry:** SaaS, fintech, healthtech
- **Budget:** $0-50/mo per seat
- **Security Team:** 0-5 people (often wearing multiple hats)
- **AI Usage:** Daily (ChatGPT, Claude, GitHub Copilot)

### Pain Points
1. "I don't want to accidentally leak customer data to AI"
2. "I need to comply with SOC 2 / HIPAA / PCI-DSS"
3. "I don't have time to configure complex security tools"
4. "I can't afford $50K/year enterprise solutions"
5. "I don't want my prompts sent to another cloud service"
6. "I need to prove to auditors that we're protecting data"

### What Sarah Buys
| Feature | Importance | Willingness to Pay |
|---------|------------|-------------------|
| **Just works out of box** | CRITICAL | Included |
| **Detects PII/secrets** | CRITICAL | Included |
| **Blocks violations** | HIGH | Included |
| **No phone-home** | HIGH | Included |
| **Slack alerts** | MEDIUM | $5/mo |
| **Audit log search** | MEDIUM | $5/mo |
| **Compliance mappings** | HIGH | Included |
| **Auto-updates** | MEDIUM | Included |
| **SSO integration** | LOW (not needed) | $0 |
| **SIEM integration** | LOW (no SIEM) | $0 |
| **Kubernetes** | LOW (uses VMs) | $0 |
| **Multi-tenancy** | LOW (single team) | $0 |

### Sarah's Buying Journey
```
1. Hears about AegisGate (Hacker News, Twitter, colleague)
2. Visits website → sees "open source, privacy-first"
3. Installs via brew/deb/rpm (5 minutes)
4. Configures CA cert (2 minutes)
5. Gets first violation alert (instant value)
6. Tells team about it (viral growth)
7. Upgrades to Pro ($29/mo) for support + updates
8. Becomes advocate (case study, referral)
```

**Total Time to Value:** <10 minutes  
**Conversion Rate:** 5-10% (free → paid)  
**LTV:** $348-696 (1-2 years retention)

---

## The 5% Persona: "Enterprise CISO Michael"

### Profile
- **Role:** CISO / VP Security
- **Company:** 500-10,000+ employees (enterprise)
- **Industry:** Finance, healthcare, government
- **Budget:** $50K-500K/year
- **Security Team:** 50-500 people
- **AI Usage:** Organization-wide (thousands of users)

### Pain Points
1. "I need visibility into ALL AI usage across the org"
2. "I need to integrate with our existing SIEM (Splunk, QRadar)"
3. "I need SSO (Okta, Azure AD) for access control"
4. "I need centralized policy management"
5. "I need compliance reports for auditors"
6. "I need to deploy in Kubernetes (our standard)"
7. "I need multi-tenancy (different teams, different policies)"
8. "I need custom ML models (industry-specific threats)"

### What Michael Buys
| Feature | Importance | Willingness to Pay |
|---------|------------|-------------------|
| **SSO/SAML** | CRITICAL | $10K/yr |
| **SIEM integration** | CRITICAL | $10K/yr |
| **Centralized policy** | CRITICAL | $20K/yr |
| **Multi-tenancy** | HIGH | $10K/yr |
| **Kubernetes/Helm** | HIGH | $5K/yr |
| **Compliance reports** | HIGH | $10K/yr |
| **Custom ML models** | MEDIUM | $20K/yr |
| **Batch scanning** | MEDIUM | $5K/yr |
| **Advanced search** | MEDIUM | $5K/yr |
| **Per-user quotas** | LOW | Included |
| **Auto-updates** | LOW | Included |
| **Basic detection** | LOW (commodity) | $0 |

### Michael's Buying Journey
```
1. Security team evaluates AI security vendors (3-6 months)
2. RFP process (AegisGate vs. Nightfall vs. Protect AI)
3. POC deployment (2-4 weeks)
4. Security review (penetration test, architecture review)
5. Legal review (MSA, DPA, SLA)
6. Procurement negotiation (pricing, terms)
7. Enterprise deployment (hundreds of seats)
8. Ongoing management (policy tuning, reporting)
```

**Total Time to Value:** 6-12 months  
**Conversion Rate:** 20-30% (POC → contract)  
**LTV:** $150K-500K (3-year contract)

---

## Feature Prioritization Matrix

### CRITICAL for 95% (Build First) ✅

| Feature | Status | Effort | Impact | Priority |
|---------|--------|--------|--------|----------|
| **Easy installation** | ✅ DONE | N/A | HIGH | P0 |
| **Just works (sensible defaults)** | ✅ DONE | N/A | HIGH | P0 |
| **PII/secret detection** | ✅ DONE | N/A | HIGH | P0 |
| **Block mode** | ✅ DONE | N/A | HIGH | P0 |
| **No phone-home (privacy)** | ✅ DONE | N/A | HIGH | P0 |
| **Affordable pricing** | ✅ DONE | N/A | HIGH | P0 |
| **Good documentation** | ✅ DONE | N/A | HIGH | P0 |
| **Auto-updates** | ✅ DONE | N/A | MEDIUM | P0 |

**Total:** 8/8 critical features complete ✅

---

### HIGH for 95% (Build Next) ⚠️

| Feature | Status | Effort | Impact | Priority |
|---------|--------|--------|--------|----------|
| **Slack/Discord webhooks** | ⚠️ EXISTS (Platform) | 1-2 days | MEDIUM | P1 |
| **Basic audit log search** | ❌ Linear scan | 2-3 days | MEDIUM | P1 |
| **Desktop notifications** | ✅ DONE | N/A | HIGH | P1 |
| **System tray integration** | ✅ DONE | N/A | MEDIUM | P1 |
| **Config integrity check** | ✅ DONE | N/A | MEDIUM | P1 |
| **Binary verification** | ✅ DONE | N/A | MEDIUM | P1 |
| **Log encryption** | ✅ DONE | N/A | HIGH | P1 |

**Total:** 5/7 complete, 2 quick wins remaining (3-5 days)

---

### MEDIUM for 95% (Nice to Have) 📋

| Feature | Status | Effort | Impact | Priority |
|---------|--------|--------|--------|----------|
| **Compliance report generation** | ⚠️ Mappings only | 3-4 days | MEDIUM | P2 |
| **Batch scanning (historical)** | ❌ Not built | 3-4 days | MEDIUM | P2 |
| **Custom regex patterns** | ✅ DONE | N/A | LOW | P2 |
| **Per-user rate limiting** | ❌ Global only | 2-3 days | LOW | P3 |
| **Browser extension (web AI)** | ❌ Not built | 5-7 days | MEDIUM | P2 |

**Total:** 1/5 complete, 4 features (13-18 days)

---

### ENTERPRISE ONLY (5% Needs) 🏢

| Feature | Status | Effort | Impact (95%) | Impact (5%) | Priority |
|---------|--------|--------|--------------|-------------|----------|
| **SSO/SAML** | ✅ EXISTS (Platform) | 3-4 days (port) | LOW | CRITICAL | Enterprise |
| **SIEM integration** | ✅ EXISTS (Platform) | 2-3 days (port) | LOW | CRITICAL | Enterprise |
| **Centralized policy** | ✅ EXISTS (Platform) | 3-4 days (sync) | LOW | CRITICAL | Enterprise |
| **Multi-tenancy** | ✅ EXISTS (Platform) | 5-7 days (partial) | LOW | HIGH | Enterprise |
| **Kubernetes/Helm** | ❌ Not built | 2-3 days | LOW | HIGH | Enterprise |
| **Custom ML models** | ✅ EXISTS (Lens) | 5-7 days (self-serve) | LOW | MEDIUM | Enterprise |
| **Advanced search/indexing** | ❌ Not built | 2-3 days | MEDIUM | HIGH | Both |
| **Compliance reports (auto)** | ⚠️ Mappings only | 3-4 days | MEDIUM | HIGH | Both |
| **Batch scanning** | ❌ Not built | 3-4 days | MEDIUM | MEDIUM | Both |

**Key Insight:** Most enterprise features already exist in Platform. Porting is 2-7 days each, not months.

---

## The 95% Roadmap (v0.5.1 → v0.7.0)

### v0.5.1 — Ship NOW ✅
**Theme:** "Privacy Complete"
- ✅ 15/16 P2 items
- ⏳ P2#10 documented (deferred)
- **Ready for 95% adoption**

**Time to Market:** NOW  
**Target:** Developers, SMBs, security-conscious teams

---

### v0.6.0 — Quick Wins (2-3 weeks)
**Theme:** "Alerts + Integrity"

**For the 95%:**
1. ⭐ **Webhook integrations** (Slack, Discord, Teams) — 1-2 days
   - Port from Platform webhook package
   - Pre-configured templates for common services
   - Custom webhook support

2. ⭐ **Full cosign verification** — 1-2 days
   - Complete cryptographic signature verification
   - Auto-verify on update check
   - CLI command: `rampart verify-binary`

3. ⭐ **Basic audit log search** — 2-3 days
   - Simple grep-like search (no full indexing yet)
   - Filter by date, severity, category
   - CLI command: `rampart audit-search --query "SSN"`

4. ⭐ **Memory zeroing (memguard)** — 3-5 days
   - Secure buffers for passphrases
   - Memory locking (mlock)
   - Document remaining limitations

**Total Effort:** 7-12 days  
**Target:** Enhanced security + usability for 95%

---

### v0.7.0 — Enhanced Usability (2-3 months)
**Theme:** "Developer Experience"

**For the 95%:**
1. **Compliance report generation** — 3-4 days
   - PDF/HTML reports for auditors
   - SOC 2, HIPAA, PCI-DSS templates
   - CLI command: `rampart compliance-report --framework SOC2`

2. **Batch scanning** — 3-4 days
   - Scan existing codebases
   - SARIF output (IDE integration)
   - CLI command: `rampart scan ./path/to/code`

3. **Browser extension (web AI)** — 5-7 days
   - Chrome/Firefox extension
   - Protect ChatGPT, Claude web usage
   - Same detection engine as Lens

4. **Advanced audit log search** — 2-3 days
   - Bleve full-text indexing
   - Field-based queries
   - Pagination for large result sets

**Total Effort:** 13-18 days  
**Target:** Power users, compliance teams, broader AI coverage

---

### v0.8.0+ — Enterprise Upsell (6+ months)
**Theme:** "Enterprise Ready"

**For the 5%:**
1. **SSO/SAML integration** — 3-4 days (port from Platform)
2. **SIEM connectors** — 2-3 days (port from Platform)
3. **Platform policy sync** — 3-4 days (agent integration)
4. **Kubernetes/Helm** — 2-3 days (new)
5. **Multi-tenancy (partial)** — 5-7 days (port from Platform)
6. **Custom ML (self-serve)** — 5-7 days (extend Lens pipeline)

**Total Effort:** 20-28 days  
**Target:** Enterprise customers ($50K-500K contracts)

---

## Revenue Model: 95% vs. 5%

### 95% Revenue (Volume)

| Tier | Price | Target | Year 1 Customers | Year 1 Revenue |
|------|-------|--------|------------------|----------------|
| **Community** | $0 | Developers | 25,000 | $0 |
| **Pro** | $29/mo | Individuals | 400 | $139K |
| **Team** | $99/mo | SMBs (10 seats) | 80 | $95K |
| **Total** | — | — | **500** | **$234K** |

**Characteristics:**
- Self-serve signup (no sales call)
- Credit card checkout
- 5-10% conversion (free → paid)
- Low CAC ($50-100 via content/community)
- High LTV:CAC (30x+)

---

### 5% Revenue (Value)

| Tier | Price | Target | Year 1 Customers | Year 1 Revenue |
|------|-------|--------|------------------|----------------|
| **Enterprise** | $5K/mo | Mid-market (500 seats) | 10 | $600K |
| **Enterprise+** | $20K/mo | Large enterprise (2K+ seats) | 2 | $480K |
| **Total** | — | — | **12** | **$1.08M** |

**Characteristics:**
- Sales-assisted (POC, negotiation)
- Annual contracts
- 20-30% conversion (POC → contract)
- High CAC ($5K-10K via sales cycle)
- High LTV:CAC (10x+)

---

### Combined Year 1 Projection

| Segment | Customers | Revenue | % of Total |
|---------|-----------|---------|------------|
| **95% (SMB/Dev)** | 500 | $234K | 18% |
| **5% (Enterprise)** | 12 | $1.08M | 82% |
| **Total** | 512 | $1.314M | 100% |

**Key Insight:** The 95% drives **adoption** (500 customers, community, viral growth). The 5% drives **revenue** (12 customers, 82% of total).

**Strategy:** 
1. Build for the 95% first (volume, community, product-market fit)
2. Upsell the 5% (enterprise features, high-value contracts)
3. Use 95% feedback to improve product (enterprise benefits)
4. Use 5% revenue to fund development (sustainable growth)

---

## What the 95% REALLY Wants (Psychological Analysis)

### 1. **Peace of Mind** (Not Features)
Sarah doesn't want "153 regex patterns" — she wants to **sleep at night** knowing she won't accidentally leak customer data.

**What This Means:**
- ✅ Simple installation (not "configure 20 settings")
- ✅ Sensible defaults (not "read 100-page docs")
- ✅ Clear alerts (not "cryptic error messages")
- ✅ Automatic updates (not "manual patching")

---

### 2. **Control** (Not Complexity)
Sarah wants to **feel in control** of her AI usage, not be overwhelmed by options.

**What This Means:**
- ✅ Block mode (active prevention, not just detection)
- ✅ Desktop notifications (real-time feedback)
- ✅ Simple config (JSON, not YAML with 500 options)
- ✅ Audit log (see what was blocked, not just "something happened")

---

### 3. **Privacy** (Not Promises)
Sarah doesn't trust cloud services with her data. She wants **proof**, not marketing.

**What This Means:**
- ✅ Zero phone-home by default (not "opt-out telemetry")
- ✅ Open source (auditable, not "trust us")
- ✅ Local ML (no cloud dependency)
- ✅ Encrypted audit logs (even local files are protected)

---

### 4. **Affordability** (Not Enterprise Pricing)
Sarah has a **$50/mo budget**, not $50K/year.

**What This Means:**
- ✅ $0-49/mo pricing (not "contact sales")
- ✅ Self-serve checkout (not "schedule a demo")
- ✅ No hidden fees (not "per-seat, per-feature, per-usage")
- ✅ Cancel anytime (not "3-year contract")

---

### 5. **Community** (Not Vendor Lock-in)
Sarah wants to be part of a **movement**, not tied to a vendor.

**What This Means:**
- ✅ Open source (Apache 2.0, not proprietary)
- ✅ GitHub community (issues, PRs, discussions)
- ✅ Transparent roadmap (not "vaporware promises")
- ✅ User-driven development (not "enterprise-only features")

---

## Competitive Positioning for the 95%

### vs. Nightfall AI ($50K/year)
| Feature | AegisGate | Nightfall | Winner (95%) |
|---------|-----------|-----------|--------------|
| **Price** | $0-49/mo | $50K/yr | ✅ AegisGate (1000x cheaper) |
| **Installation** | 5 minutes | Enterprise deployment | ✅ AegisGate |
| **Privacy** | Zero phone-home | Cloud-only | ✅ AegisGate |
| **Open Source** | Yes (Apache 2.0) | No | ✅ AegisGate |
| **Self-Serve** | Yes (credit card) | No (sales call) | ✅ AegisGate |

**95% Verdict:** AegisGate wins on **price, privacy, simplicity**

---

### vs. Lakera ($99/mo)
| Feature | AegisGate | Lakera | Winner (95%) |
|---------|-----------|--------|--------------|
| **Price** | $0-49/mo | $99/mo | ✅ AegisGate (2x cheaper) |
| **Privacy** | Zero phone-home | Some cloud data | ✅ AegisGate |
| **Open Source** | Yes | No | ✅ AegisGate |
| **Block Mode** | Yes | Warn only | ✅ AegisGate |
| **Audit Logs** | Encrypted, local | Cloud storage | ✅ AegisGate |

**95% Verdict:** AegisGate wins on **price, privacy, control**

---

### vs. Protect AI (Custom Pricing)
| Feature | AegisGate | Protect AI | Winner (95%) |
|---------|-----------|------------|--------------|
| **Price** | $0-49/mo | Custom (expensive) | ✅ AegisGate |
| **Target** | SMB + Enterprise | Enterprise only | ✅ AegisGate (accessible) |
| **Installation** | 5 minutes | Enterprise deployment | ✅ AegisGate |
| **Self-Serve** | Yes | No | ✅ AegisGate |

**95% Verdict:** AegisGate wins on **accessibility, simplicity**

---

## The 95% Go-to-Market Strategy

### Phase 1: Community Building (Months 1-6)
**Goal:** 25,000 free users, 500 paid conversions

**Channels:**
1. **GitHub** — Open source launch, stars, forks, contributors
2. **Hacker News** — "Show HN: AegisGate Rampart"
3. **Reddit** — r/devops, r/cybersecurity, r/privacy
4. **Twitter/LinkedIn** — Security influencer outreach
5. **Content Marketing** — Blog posts, tutorials, case studies

**Metrics:**
- 10K GitHub stars
- 5K active users
- 500 paid customers
- $20K MRR

---

### Phase 2: SMB Sales (Months 7-18)
**Goal:** 5,000 paid customers, $70K MRR

**Channels:**
1. **Self-Serve** — Website, free trial, credit card checkout
2. **Content** — SEO, webinars, whitepapers
3. **Partnerships** — MSPs, VARs, cloud marketplaces
4. **Referrals** — Incentivize word-of-mouth
5. **Customer Success** — Onboarding, support, retention

**Metrics:**
- $70K MRR
- 80% retention rate
- 5% conversion (free → paid)
- Break-even cash flow

---

### Phase 3: Enterprise Upsell (Months 19-36)
**Goal:** 50 enterprise customers, $250K MRR

**Channels:**
1. **Direct Sales** — Sales team, enterprise outreach
2. **Platform Integration** — SSO, SIEM, policy sync
3. **Conferences** — RSA, Black Hat, Gartner Security
4. **Analyst Relations** — Gartner, Forrester, IDC
5. **Certifications** — SOC 2, FedRAMP, HIPAA

**Metrics:**
- $250K MRR
- 95% retention rate
- 6-month sales cycle
- Profitable operations

---

## Conclusion: Serve the 95% First

**The 95% needs:**
- ✅ Easy installation (DONE)
- ✅ Just works (DONE)
- ✅ Detects violations (DONE)
- ✅ Blocks threats (DONE)
- ✅ Privacy-first (DONE)
- ✅ Affordable (DONE)
- ⚠️ Simple alerts (1-2 days — webhooks)
- ⚠️ Basic search (2-3 days — grep-like)

**The 5% needs:**
- ⚠️ SSO/SAML (exists in Platform, port 3-4 days)
- ⚠️ SIEM integration (exists in Platform, port 2-3 days)
- ⚠️ Centralized policy (exists in Platform, sync 3-4 days)
- ❌ Kubernetes/Helm (build 2-3 days)
- ❌ Batch scanning (build 3-4 days)

**Strategy:**
1. **Ship v0.5.1 NOW** — Serve the 95% (volume, community)
2. **v0.6.0: Quick wins** — Webhooks, cosign, basic search (7-12 days)
3. **v0.7.0: Enhanced UX** — Compliance reports, batch scanning, browser extension (13-18 days)
4. **v0.8.0+: Enterprise** — SSO, SIEM, K8s, multi-tenancy (20-28 days)

**Revenue Model:**
- 95% drives **adoption** (500 customers, $234K Year 1)
- 5% drives **revenue** (12 customers, $1.08M Year 1)
- Combined: **$1.3M Year 1**, sustainable growth

**Bottom Line:** Build for Sarah (the 95%), upsell Michael (the 5%). The 95% gets a great product at an affordable price. The 5% gets enterprise features when they're ready. Everyone wins.

---

**Last Updated:** 2026-08-08  
**Status:** 95% READY TO SHIP ✅
