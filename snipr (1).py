#!/usr/bin/env python3
"""
Snipr
-----

Snipr is a lightweight, fast HTTP fuzzer inspired by the Burp Suite “Intruder\Sniper” attack
mode.  The goal is to provide comparable functionality for testers who don’t have access
to a commercial licence, while remaining easy to install and simple to operate.

This script takes a single **injection point** (a marker string) in the target URL,
headers, or request body and replaces it with each payload in turn.  Requests are issued
concurrently using Python’s `ThreadPoolExecutor` to maximise throughput while still
respecting user‑defined timeouts and retry behaviour.  You can source payloads from a
file, generate numeric ranges on the fly, or specify an inline comma‑separated list.

Key Features
============

* **Single injection point.** Specify a marker (default `{{FUZZ}}`) in the URL, request
  body, or header values.  Every occurrence of the marker is replaced with each payload.
* **Flexible payload sources.** Load payloads from a text file (`--payloads`), generate
  an inclusive numeric range (`--range start end step`), or supply a comma‑separated
  inline list (`--list`).
* **Concurrency and retries.** Control the number of worker threads (`--threads`), per
  request timeout (`--timeout`), and number of retries (`--retries`).
* **Optional proxy and TLS verification toggle.** Point traffic through Burp or any
  upstream proxy with `--proxy`, and disable certificate verification with `--insecure`.
* **Content grepping and extraction.** Provide regular expressions to mark matching
  responses (`--grep`) or extract a value (`--extract`) from the response body.
* **Output filtering and export.** Filter results by HTTP status (`--filter-status`),
  only show matches (`--only-matches`), and save results to CSV or JSON (`--out-csv`,
  `--out-json`).
* **Progress reporting.** Enable verbose progress output (`--verbose`) to see each
  request as it completes.

Example Usage
-------------

```
python3 snipr.py --url "https://example.com/search?q={{FUZZ}}" \
                 --list admin,guest,root \
                 --header "User-Agent: Snipr/1.0" \
                 --threads 10 --timeout 5 --grep "Welcome back" --extract "Hello, (.*?)!" \
                 --out-csv results.csv --verbose

```

The above command will concurrently request `https://example.com/search?q=admin`,
`https://example.com/search?q=guest`, and `https://example.com/search?q=root`, marking
responses containing the phrase “Welcome back” and capturing the first word following
`Hello, `.  Results are saved to `results.csv` and also displayed in the terminal.

Dependencies
============

This script intentionally keeps external dependencies to a minimum; only the
`requests` library is required.  Install it via:

```
pip install requests
```

"""
import argparse, csv, json, os, re, sys, time, threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlsplit
import requests

def parse_headers(hlist):
    headers = {}
    for h in hlist or []:
        if ":" not in h:
            raise argparse.ArgumentTypeError(f"Invalid header '{h}'. Use 'Key: Value'.")
        k, v = h.split(":", 1)
        headers[k.strip()] = v.strip()
    return headers

def load_payloads(args):
    """Return an ordered list of payloads based on the provided arguments.

    The user may supply payloads via a file, numeric range, or comma‑separated list.
    All sources are concatenated in the order they appear.  Whitespace‑only lines are
    ignored.
    """
    items: list[str] = []
    # From file
    if args.payloads:
        try:
            with open(args.payloads, "r", encoding="utf-8", errors="ignore") as f:
                items.extend([ln.rstrip("\n") for ln in f if ln.strip()])
        except OSError as e:
            raise SystemExit(f"Could not read payloads file '{args.payloads}': {e}")
    # From numeric range
    if args.range:
        start, end, step = args.range
        # Adjust inclusive end depending on sign of step
        inclusive_end = end + (1 if step > 0 else -1)
        items.extend([str(i) for i in range(start, inclusive_end, step)])
    # From inline list
    if args.list:
        items.extend([x.strip() for x in args.list.split(",") if x.strip()])
    if not items:
        raise SystemExit("No payloads provided. Use --payloads, --range, or --list.")
    return items

def build_request(args, payload):
    marker = args.marker
    url = args.url.replace(marker, payload)
    headers = dict(args.headers)
    for hk in list(headers.keys()):
        headers[hk] = headers[hk].replace(marker, payload)
    data = None
    if args.data is not None:
        data = args.data.replace(marker, payload)
    return url, headers, data

def compile_regex_or_none(pattern):
    if not pattern:
        return None
    try:
        return re.compile(pattern, re.I | re.S)
    except re.error as e:
        raise SystemExit(f"Invalid regex '{pattern}': {e}")

def request_once(session, method, url, headers, data, timeout, allow_redirects):
    start = time.perf_counter()
    resp = session.request(method=method, url=url, headers=headers, data=data,
                           timeout=timeout, allow_redirects=allow_redirects)
    elapsed_ms = int((time.perf_counter() - start) * 1000)
    return resp, elapsed_ms

def worker(session_factory, args, payload, grep_re, extract_re):
    url, headers, data = build_request(args, payload)
    tries = args.retries + 1
    last_err = None
    for attempt in range(tries):
        try:
            session = session_factory()
            resp, elapsed_ms = request_once(session, args.method, url, headers, data,
                                            args.timeout, args.redirects)
            body = resp.text or ""
            match = bool(grep_re.search(body)) if grep_re else None
            extract = None
            if extract_re:
                m = extract_re.search(body)
                extract = m.group(1) if (m and m.groups()) else (m.group(0) if m else None)
            result = {
                "payload": payload,
                "status": resp.status_code,
                "length": len(body),
                "time_ms": elapsed_ms,
                "matched": match,
                "extract": extract,
                "url": url,
            }
            return result
        except Exception as e:
            last_err = str(e)
            if attempt < tries - 1:
                time.sleep(0.1 * (attempt + 1))
            else:
                return {
                    "payload": payload, "status": None, "length": 0, "time_ms": None,
                    "matched": None, "extract": None, "url": url, "error": last_err
                }

def make_session_factory(args):
    # One session per thread to reuse connections
    local = threading.local()
    def factory():
        if getattr(local, "session", None) is None:
            s = requests.Session()
            if args.proxy:
                s.proxies.update({"http": args.proxy, "https": args.proxy})
            s.verify = not args.insecure
            adapter = requests.adapters.HTTPAdapter(pool_connections=1000, pool_maxsize=1000)
            s.mount("http://", adapter); s.mount("https://", adapter)
            local.session = s
        return local.session
    return factory

def write_outputs(results, args):
    if args.out_csv:
        with open(args.out_csv, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=list(results[0].keys()))
            writer.writeheader(); writer.writerows(results)
    if args.out_json:
        with open(args.out_json, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)

def print_table(results, show_errors=True):
    # minimal table without extra deps
    headers = ["#", "payload", "status", "len", "ms", "match", "extract", "error"]
    col_widths = {h: len(h) for h in headers}
    for i, r in enumerate(results, 1):
        cells = [
            str(i),
            r["payload"],
            str(r.get("status")),
            str(r.get("length")),
            str(r.get("time_ms")),
            str(r.get("matched")) if r.get("matched") is not None else "",
            (r.get("extract") or "")[:80],
            (r.get("error") or "")[:60] if show_errors else "",
        ]
        for h, c in zip(headers, cells):
            col_widths[h] = max(col_widths[h], len(c))
    fmt = "  ".join("{:<" + str(col_widths[h]) + "}" for h in headers)
    print(fmt.format(*headers))
    print("-" * (sum(col_widths.values()) + 2 * (len(headers) - 1)))
    for i, r in enumerate(results, 1):
        cells = [
            str(i),
            r["payload"],
            str(r.get("status")),
            str(r.get("length")),
            str(r.get("time_ms")),
            str(r.get("matched")) if r.get("matched") is not None else "",
            (r.get("extract") or "")[:80],
            (r.get("error") or "")[:60] if show_errors else "",
        ]
        print(fmt.format(*cells))

def main():
    p = argparse.ArgumentParser(
        description=(
            "Snipr is a lightweight HTTP fuzzer that emulates Burp's 'Sniper' mode. "
            "Use a marker in the URL, headers, or body and supply a list of payloads."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    # Target definition
    p.add_argument("--url", required=True, help="Target URL containing the marker string")
    p.add_argument("--method", default="GET", help="HTTP method to use")
    p.add_argument("--data", help="Request body; the marker will be replaced here as well")
    p.add_argument("--header", dest="headers", action="append", help="Custom header 'Key: Value' (repeatable)")
    p.add_argument("--marker", default="{{FUZZ}}", help="Marker string to be replaced with each payload")

    # Payload sources
    p.add_argument("--payloads", help="Read payloads from a file (one per line)")
    p.add_argument(
        "--range",
        nargs=3,
        type=int,
        metavar=("START", "END", "STEP"),
        help="Generate numeric payloads inclusively (e.g., --range 1 255 1)",
    )
    p.add_argument("--list", help="Comma-separated list of payloads (e.g., 'admin,root,test')")

    # Performance controls
    p.add_argument("--threads", type=int, default=30, help="Number of concurrent worker threads")
    p.add_argument("--timeout", type=float, default=10.0, help="Request timeout in seconds")
    p.add_argument("--retries", type=int, default=1, help="Number of retries on failure")
    p.add_argument("--redirects", action="store_true", help="Follow HTTP redirects")
    p.add_argument("--proxy", help="Proxy URL to route traffic through (e.g., http://127.0.0.1:8080)")
    p.add_argument("--insecure", action="store_true", help="Disable TLS certificate verification")

    # Response processing
    p.add_argument("--grep", help="Regex to flag matching responses (adds a true/false column)")
    p.add_argument("--extract", help="Regex to extract a value from the response body")
    p.add_argument(
        "--filter-status",
        help="Only include rows with these comma-separated HTTP status codes (e.g., 200,404,403)",
    )
    p.add_argument(
        "--only-matches",
        action="store_true",
        help="Only include results where the grep or extract patterns matched",
    )

    # Output control
    p.add_argument("--out-csv", dest="out_csv", help="Save results to a CSV file")
    p.add_argument("--out-json", dest="out_json", help="Save results to a JSON file")
    p.add_argument(
        "--verbose",
        action="store_true",
        help="Print a progress line as each request completes",
    )

    args = p.parse_args()

    # Parse and validate headers
    args.headers = parse_headers(args.headers)
    # Ensure that the marker exists somewhere in the URL, headers or body
    marker = args.marker
    marker_present = False
    if marker and marker in (args.url or ""):
        marker_present = True
    if not marker_present and args.data and marker in args.data:
        marker_present = True
    if not marker_present:
        for val in args.headers.values():
            if marker in val:
                marker_present = True
                break
    if not marker_present:
        raise SystemExit(
            f"Marker '{marker}' not found in URL, headers or data. "
            "Include the marker in at least one of these locations."
        )

    # Build payload list
    payloads = load_payloads(args)
    grep_re = compile_regex_or_none(args.grep)
    extract_re = compile_regex_or_none(args.extract)
    session_factory = make_session_factory(args)

    # Display basic info
    target_host = urlsplit(args.url).netloc.replace(args.marker, "*")
    print(f"[i] Target: {args.method} {args.url}")
    print(f"[i] Host:   {target_host}")
    print(
        f"[i] Payloads: {len(payloads)}  | Threads: {args.threads} | Timeout: {args.timeout}s "
        f"| Retries: {args.retries}"
    )

    results: list[dict] = []
    total = len(payloads)
    # Use ThreadPoolExecutor to run workers concurrently
    with ThreadPoolExecutor(max_workers=args.threads) as exe:
        futures = {exe.submit(worker, session_factory, args, pl, grep_re, extract_re): pl for pl in payloads}
        for idx, fut in enumerate(as_completed(futures), 1):
            res = fut.result()
            results.append(res)
            if args.verbose:
                # Build a short progress summary
                status = res.get("status") if res.get("status") is not None else "ERR"
                match_flag = (
                    "Y" if res.get("matched") else ("N" if res.get("matched") is False else "")
                )
                extract_val = res.get("extract") or ""
                print(
                    f"[{idx}/{total}] {res['payload']} -> status:{status}, len:{res.get('length')}, "
                    f"ms:{res.get('time_ms')}, match:{match_flag}, extract:{extract_val[:40]}"
                )

    # Sort results by status and then by length (stable)
    results.sort(key=lambda r: (r.get("status") is None, r.get("status"), r.get("length")))

    # Filter by HTTP status codes if requested
    if args.filter_status:
        wanted = {
            int(x.strip())
            for x in args.filter_status.split(",")
            if x.strip().isdigit()
        }
        results = [r for r in results if (r.get("status") in wanted)]

    # Filter out non‑matching responses if --only-matches was specified
    if args.only_matches:
        def match_filter(r: dict) -> bool:
            # Consider both grep and extract
            if r.get("matched") is True:
                return True
            if r.get("extract"):
                return True
            return False
        results = [r for r in results if match_filter(r)]

    # Print table of results to stdout
    if results:
        print_table(results)
    else:
        print("[i] No results to display (all responses filtered out).")

    # Write outputs if requested
    if args.out_csv or args.out_json:
        write_outputs(results, args)
        out_paths = [p for p in [args.out_csv, args.out_json] if p]
        print("[i] Saved results:", ", ".join(out_paths))

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
        sys.exit(130)
