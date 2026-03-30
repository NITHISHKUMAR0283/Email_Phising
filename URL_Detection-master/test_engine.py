import requests
import json

BASE = "http://127.0.0.1:5000/api/analyze"

tests = [
    ("https://google.com", "SAFE"),
    ("https://paypal.com", "SAFE"),
    ("https://www.amazon.co.uk/products", "SAFE"),
    ("http://paypa1.com/login", "PHISHING"),
    ("https://login.apple.com.secure-check.xyz", "PHISHING"),
    ("https://secure-google-login.verify-account-auth.com", "PHISHING"),
    ("https://gmail.account-security-check.info/login", "PHISHING"),
    ("https://google-mail-authentication.support/update", "PHISHING"),
    ("http://192.168.1.1/admin", "SUSPICIOUS"),
    ("https://xk2j9qp.tk/verify", "PHISHING"),
    ("https://bit.ly/3xK9mQ", "POTENTIALLY SUSPICIOUS"),
    ("https://microsoft-security.online/verify", "PHISHING"),
]

lines = []
passed = 0
for url, expected in tests:
    r = requests.post(BASE, json={"url": url}, timeout=10)
    d = r.json()
    cat = d["category"]
    score = d["risk_score"]
    ok = "PASS" if cat == expected else "FAIL"
    if cat == expected:
        passed += 1
    lines.append(f"{ok}|{url}|expected={expected}|got={cat}|score={score}|brand={d['brand_analysis']['potential_target']}")

lines.append(f"TOTAL:{passed}/{len(tests)}")

with open("test_out.txt", "w", encoding="ascii", errors="replace") as f:
    f.write("\n".join(lines))

print("Done. See test_out.txt")
