# AegisGate Test Lab

Regression testing infrastructure for AegisGate products.

## Contents

- `unified-test-harness.py` — HTTP-based test harness with `--seed` parameter for reproducible prompt selection
- `unified-corpus.json` — Test corpus (100 prompts: 54 risky + 46 benign across 12 categories)
- `mock-ollama.py` — Mock Ollama server for Docker testlab
- `baselines/` — Version-controlled baseline results for regression comparison

## Usage

```bash
# Run a test with fixed seed for reproducibility
python3 unified-test-harness.py \
  --mode proxy \
  --target http://localhost:18080/v1/chat/completions \
  --corpus unified-corpus.json \
  --requests 100 --seed 42 --delay 0.1 \
  --output results.csv
```

## Corpus Categories

- `general` — Benign prompts
- `prompt_injection` — Prompt injection attacks
- `pii_financial` — Credit card, bank account, SSN
- `pii_us_core` — SSN, phone, email, address
- `pii_us_extended` — PHI, medical, Medicare
- `secrets` — API keys, tokens, credentials
- `malware` — Malware requests, privilege escalation
- `sqli` — SQL injection
- `xss` — Cross-site scripting
- `evasion` — Evasion techniques
- `exfiltration` — Data exfiltration
- `context_manipulation` — Context manipulation attacks
