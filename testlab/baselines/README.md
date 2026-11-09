# AegisGate Regression Baselines

## seed=42 Baseline — 2026-11-09

**Test configuration:**
- Corpus: `unified-corpus.json` (100 prompts, pipe-delimited CSV output)
- Seed: 42 (reproducible prompt selection via `random.seed()`)
- Requests: 100
- Delay: 0.1s between requests
- Rampart: v0.10.0+, commit `172a885` (PII parity fix)
- Platform: v5.1.0, commit `8d33f63c`
- ML Model: v22b (hash `948b650023984f4c24a8ea59665dcff021742bf887cfc1142b3553d57ac1460e`)

### Results

| Product | Catch Rate | False Positive | Total | Risky | Benign |
|---------|-----------|----------------|-------|-------|--------|
| Platform | 96.3% | 2.2% | 100 | 54 | 46 |
| Rampart | 98.1% | 2.2% | 100 | 54 | 46 |

### Parity Status

✅ **Parity achieved.** Rampart (98.1%) exceeds Platform (96.3%) by 1.8%.
FP rate identical at 2.2%. The previous 11.1% gap (from 3 PII prompts:
pii_005 PHI, pii_008 credit card, pii_009 SSN+bank+routing) is eliminated.

### How to Reproduce

```bash
# Start testlab containers
cd testlab
docker compose -f docker-compose.base.yml up -d
docker compose -f docker-compose.platform.yml up -d
docker compose -f docker-compose.rampart.yml up -d

# Run Rampart test
python3 testlab/unified-test-harness.py \
  --mode proxy \
  --target http://synth-ollama:11434/v1/chat/completions \
  --proxy http://localhost:18090 \
  --corpus testlab/unified-corpus.json \
  --requests 100 --seed 42 --delay 0.1 \
  --output rampart-results.csv

# Run Platform test
python3 testlab/unified-test-harness.py \
  --mode proxy \
  --target http://localhost:18080/v1/chat/completions \
  --corpus testlab/unified-corpus.json \
  --requests 100 --seed 42 --delay 0.1 \
  --output platform-results.csv

# Compare
python3 testlab/compare-results.py rampart-results.csv platform-results.csv
```

### Files

- `rampart-seed42-2026-11-09.csv` — Rampart baseline results
- `platform-seed42-2026-11-09.csv` — Platform baseline results
