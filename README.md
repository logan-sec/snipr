# Snipr 🔫

Snipr is a lightweight, fast HTTP fuzzer inspired by Burp Suite's **Intruder Sniper** mode.  
It helps security researchers and bug bounty hunters fuzz a single injection point with speed and flexibility — without needing Burp Pro.

---

## ✨ Features
- Replace a marker (`{{FUZZ}}`) in **URL, headers, or body**
- Payloads from file, inline list, or numeric range
- Concurrency with thread pooling
- Timeout, retry, and proxy support
- Grep & extract with regex
- Export results to CSV/JSON
- Minimal dependencies: `requests`

---

## ⚡ Usage
```bash
python3 snipr.py --url "https://site.com/search?q={{FUZZ}}" --list admin,guest,root

