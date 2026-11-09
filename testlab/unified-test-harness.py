#!/usr/bin/env python3
"""
AegisGate Unified Test Harness
==============================
Single test harness for all AegisGate product tests. Uses unified-corpus.json
(100 prompts: 25 PII/secrets, 25 adversarial, 50 benign) for apples-to-apples
comparison across all test configurations.

Modes:
  --mode proxy   : Send HTTP requests directly to a proxy/reverse-proxy endpoint
  --mode lens    : Use Playwright to drive a browser with Lens extension

Usage:
  # Proxy mode — Platform standalone (reverse proxy)
  python3 unified-test-harness.py --mode proxy \
    --target http://localhost:18080/v1/chat/completions \
    --requests 2500 --output results/test-pc.csv

  # Proxy mode — Rampart standalone (forward proxy to mock-ollama)
  python3 unified-test-harness.py --mode proxy \
    --target http://localhost:11434/v1/chat/completions \
    --proxy http://localhost:18090 \
    --requests 2500 --output results/test-rampart.csv

  # Proxy mode — Rampart + Platform (forward proxy to Platform)
  python3 unified-test-harness.py --mode proxy \
    --target http://localhost:18080/v1/chat/completions \
    --proxy http://localhost:18090 \
    --requests 2500 --output results/test-rpc.csv

  # Lens mode — Lens standalone
  python3 unified-test-harness.py --mode lens \
    --extension /path/to/aegisgate-lens/dist \
    --mock-url http://localhost:8888/ \
    --requests 2500 --output results/test-lens.csv

  # Lens mode — Lens + Rampart (browser uses Rampart as forward proxy)
  python3 unified-test-harness.py --mode lens \
    --extension /path/to/aegisgate-lens/dist \
    --mock-url http://localhost:8888/ \
    --forward-proxy http://localhost:18090 \
    --requests 2500 --output results/test-lr.csv

  # Lens mode — Lens + Platform (mock chat server proxies to Platform)
  # Start mock-chat-server with BACKEND_URL=http://localhost:18080/v1/chat/completions
  python3 unified-test-harness.py --mode lens \
    --extension /path/to/aegisgate-lens/dist \
    --mock-url http://localhost:8888/ \
    --requests 2500 --output results/test-lpc.csv

Output format (pipe-delimited):
  timestamp|role|category|is_risky|http_status|result|prompt_id|prompt
"""

import argparse
import json
import os
import random
import sys
import time
from datetime import datetime, timezone

ROLES = ["parent", "student", "worker", "senior", "general"]

def load_corpus(path):
    with open(path) as f:
        return json.load(f)

def select_prompt(corpus):
    """Select a prompt with 50/50 risky/benign split."""
    risky = [p for p in corpus if p["is_risky"]]
    benign = [p for p in corpus if not p["is_risky"]]
    if random.random() < 0.5:
        return random.choice(risky)
    else:
        return random.choice(benign)

def write_results(path, results):
    with open(path, "w") as f:
        f.write("timestamp|role|category|is_risky|http_status|result|prompt_id|prompt\n")
        f.write("\n".join(results) + "\n")

def run_proxy_mode(args, corpus):
    """Send HTTP requests to a reverse proxy or through a forward proxy."""
    import urllib.request
    import urllib.error

    target = args.target
    forward_proxy = args.proxy
    delay = args.delay
    model = args.model

    # Set up proxy handler if forward proxy is specified
    if forward_proxy:
        proxy_handler = urllib.request.ProxyHandler({"http": forward_proxy, "https": forward_proxy})
        opener = urllib.request.build_opener(proxy_handler)
    else:
        opener = urllib.request.build_opener()

    results = []
    for i in range(args.requests):
        prompt_data = select_prompt(corpus)
        role = random.choice(ROLES)

        body = json.dumps({
            "model": model,
            "messages": [{"role": "user", "content": prompt_data["prompt"]}]
        }).encode()

        req = urllib.request.Request(
            target,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST"
        )

        status = 0
        result = "error"
        try:
            resp = opener.open(req, timeout=30)
            status = resp.getcode()
            result = "passed"
        except urllib.error.HTTPError as e:
            status = e.code
            result = "blocked" if status == 403 else f"error_{status}"
        except Exception:
            status = 0
            result = "error"

        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        row = f'{timestamp}|{role}|{prompt_data["category"]}|{prompt_data["is_risky"]}|{status}|{result}|{prompt_data["id"]}|{prompt_data["prompt"]}'
        results.append(row)

        if (i + 1) % 100 == 0:
            blocked = sum(1 for r in results if "|blocked|" in r)
            print(f"  [{i+1}/{args.requests}] blocked={blocked} rate={blocked/(i+1)*100:.1f}%")
            write_results(args.output, results)

        time.sleep(delay)

    return results

def run_lens_mode(args, corpus):
    """Use Playwright to drive a browser with Lens extension."""
    from playwright.sync_api import sync_playwright

    extension_path = args.extension
    mock_url = args.mock_url
    chromium_path = args.chromium or "/usr/bin/chromium"
    delay = args.delay
    forward_proxy = args.forward_proxy
    profile_dir = f"/tmp/lens-profile-{os.getpid()}"

    os.system(f"rm -rf {profile_dir}")

    results = []

    launch_args = [
        f"--disable-extensions-except={extension_path}",
        f"--load-extension={extension_path}",
        "--no-sandbox",
        "--disable-dev-shm-usage",
    ]

    proxy_config = None
    if forward_proxy:
        proxy_config = {"server": forward_proxy}
        print(f"  Browser forward proxy: {forward_proxy}")

    with sync_playwright() as p:
        context = p.chromium.launch_persistent_context(
            profile_dir,
            headless=True,
            executable_path=chromium_path,
            args=launch_args,
            proxy=proxy_config,
            ignore_default_args=["--enable-automation"],
        )

        page = context.pages[0] if context.pages else context.new_page()
        page.set_default_timeout(15000)

        for i in range(args.requests):
            prompt_data = select_prompt(corpus)
            role = random.choice(ROLES)

            page.goto(mock_url, wait_until="networkidle")

            textarea = page.query_selector("textarea")
            if not textarea:
                textarea = page.query_selector("[contenteditable='true']")
            if not textarea:
                print(f"  [{i+1}] ERROR: No input field found")
                continue

            textarea.fill(prompt_data["prompt"])

            # Wait for Lens to scan the input (ML inference + regex)
            time.sleep(delay)

            # Check for Lens banner (blocked) BEFORE trying to submit
            banner = page.query_selector('[data-aegisgate-lens="banner"]')
            is_blocked = banner is not None and banner.is_visible()

            if not is_blocked:
                # No banner — prompt passed Lens. Click submit to send.
                # Check window.__apiStatus for proxy-level blocks (Rampart 403).
                try:
                    submit = page.query_selector("button[type='submit']") or \
                             page.query_selector("button")
                    if submit:
                        submit.click(timeout=5000)
                    else:
                        textarea.press("Enter")
                    # Wait for API response — poll window.__apiStatus
                    for _ in range(10):
                        time.sleep(0.5)
                        api_status = page.evaluate("window.__apiStatus || 0")
                        if api_status > 0:
                            break
                    if api_status == 403:
                        is_blocked = True
                except Exception:
                    pass  # Click may fail if page state changed

            status = 403 if is_blocked else 200
            result = "blocked" if is_blocked else "passed"

            # Clear banner and state between prompts
            page.evaluate("""() => {
                const b = document.querySelector('[data-aegisgate-lens="banner"]');
                if (b) { b.innerHTML = ''; b.remove(); }
                const ta = document.querySelector('textarea');
                if (ta) ta.value = '';
            }""")

            timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            row = f'{timestamp}|{role}|{prompt_data["category"]}|{prompt_data["is_risky"]}|{status}|{result}|{prompt_data["id"]}|{prompt_data["prompt"]}'
            results.append(row)

            if (i + 1) % 50 == 0:
                blocked = sum(1 for r in results if "|blocked|" in r)
                print(f"  [{i+1}/{args.requests}] blocked={blocked} rate={blocked/(i+1)*100:.1f}%")
                write_results(args.output, results)

        context.close()

    os.system(f"rm -rf {profile_dir}")
    return results

def main():
    parser = argparse.ArgumentParser(description="AegisGate Unified Test Harness")
    parser.add_argument("--mode", required=True, choices=["proxy", "lens"])
    parser.add_argument("--corpus", default="unified-corpus.json")
    parser.add_argument("--requests", type=int, default=2500)
    parser.add_argument("--output", required=True)
    parser.add_argument("--delay", type=float, default=3.0)
    parser.add_argument("--target", default="http://localhost:18080/v1/chat/completions")
    parser.add_argument("--proxy", default=None, help="Forward proxy URL (e.g., http://localhost:18090)")
    parser.add_argument("--model", default="gemma3:1b")
    parser.add_argument("--extension", default=None)
    parser.add_argument("--mock-url", default="http://localhost:8888/")
    parser.add_argument("--chromium", default="/usr/bin/chromium")
    parser.add_argument("--forward-proxy", default=None, help="Browser forward proxy (Lens + Rampart combos)")
    parser.add_argument("--seed", type=int, default=None, help="Random seed for reproducible prompt selection")

    args = parser.parse_args()

    if args.seed is not None:
        random.seed(args.seed)
        print(f"Random seed: {args.seed}")
    corpus = load_corpus(args.corpus)
    risky_count = sum(1 for p in corpus if p["is_risky"])
    benign_count = sum(1 for p in corpus if not p["is_risky"])
    print(f"Corpus: {len(corpus)} prompts ({risky_count} risky, {benign_count} benign)")
    print(f"Mode: {args.mode} | Requests: {args.requests} | Delay: {args.delay}s")
    if args.mode == "proxy" and args.proxy:
        print(f"Forward proxy: {args.proxy}")
    if args.mode == "proxy":
        print(f"Target: {args.target}")
    if args.mode == "lens" and args.forward_proxy:
        print(f"Browser forward proxy: {args.forward_proxy}")
    print(f"Est. time: ~{args.requests * args.delay / 60:.0f} min ({args.requests * args.delay / 3600:.1f}h)")
    print()

    if args.mode == "proxy":
        results = run_proxy_mode(args, corpus)
    elif args.mode == "lens":
        if not args.extension:
            print("ERROR: --extension required for lens mode")
            sys.exit(1)
        results = run_lens_mode(args, corpus)

    write_results(args.output, results)

    # Final summary
    total = len(results)
    blocked = sum(1 for r in results if "|blocked|" in r)
    passed = sum(1 for r in results if "|passed|" in r)
    errors = total - blocked - passed

    risky_blocked = sum(1 for r in results if "|True|403|blocked|" in r)
    risky_passed = sum(1 for r in results if "|True|200|passed|" in r)
    benign_blocked = sum(1 for r in results if "|False|403|blocked|" in r)
    benign_passed = sum(1 for r in results if "|False|200|passed|" in r)

    print()
    print("=" * 60)
    print("FINAL RESULTS")
    print("=" * 60)
    print(f"Total: {total} | Blocked: {blocked} ({blocked/total*100:.1f}%) | Passed: {passed} | Errors: {errors}")
    if risky_blocked + risky_passed > 0:
        print(f"Risky:  {risky_blocked+risky_passed} sent, {risky_blocked} blocked ({risky_blocked/(risky_blocked+risky_passed)*100:.1f}% catch rate)")
    if benign_blocked + benign_passed > 0:
        print(f"Benign: {benign_blocked+benign_passed} sent, {benign_blocked} blocked ({benign_blocked/(benign_blocked+benign_passed)*100:.1f}% false positive rate)")

if __name__ == "__main__":
    main()