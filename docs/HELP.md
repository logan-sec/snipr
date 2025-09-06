snipr — fast single-point HTTP fuzzer (Burp “Sniper” style)

Usage:
  snipr [OPTIONS]

Options:
  --method TEXT             HTTP method (default: GET)
  --url TEXT                Target URL containing the marker (required)
  --headers TEXT            Extra headers. Either JSON dict or "Header: Val\nHeader2: Val2"
  --body TEXT               Request body (supports marker replacement)
  --marker TEXT             Marker string to replace (default: {{FUZZ}})
  --payload TEXT            Single payload value
  --payload-file PATH       File with one payload per line
  --payload-range TEXT      Numeric range, e.g. 1:9999
  --threads INTEGER         Number of concurrent threads (default: 20)
  --retries INTEGER         Per-request retries (default: 0)
  --timeout INTEGER         Timeout per request in seconds (default: 10)
  --proxy TEXT              HTTP/HTTPS proxy (e.g., http://127.0.0.1:8080)
  --grep TEXT               Regex to flag interesting responses
  --extract TEXT            Regex capture group to extract (first group)
  --out PATH                Save results to file (CSV or JSON)
  --show-len / --no-show-len
                            Show response length column (default: show)
  --help                    Show this message and exit

--method TEXT             HTTP method (default: GET)
--url TEXT                Target URL containing the marker (required)

## Examples

### Fuzz a query parameter
snipr --url "https://target.tld/search?q={{FUZZ}}" \
      --payload-file payloads/xss-basic.txt

### Brute-force numeric IDs
snipr --url "https://target.tld/item?id={{FUZZ}}" \
      --payload-range 1000:2000

