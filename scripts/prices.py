#!/usr/bin/env python3
"""Refresh prices for the money dashboard (runs in GitHub Actions; deterministic, no secrets in output).

Reads data/symbols.enc (encrypted list of Yahoo symbols and mfapi scheme codes), fetches the latest
price for each, writes data/prices.enc and updates data/status.json (timestamps and counts only).
The AES-256-GCM key comes from the DASH_KEY environment variable (base64), set as an Actions secret.
"""
import base64, datetime as dt, json, os, sys, time, urllib.parse, urllib.request
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

IST = dt.timezone(dt.timedelta(hours=5, minutes=30))
AAD = b"money-dash/v1"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SYMBOLS = os.environ.get("SYMBOLS_PATH") or os.path.join(ROOT, "data/symbols.enc")   # read from the site checkout (main)
OUT = os.environ.get("OUT_DIR") or os.path.join(ROOT, "data")                       # written to the 'data' branch checkout


def key():
    k = os.environ.get("DASH_KEY", "")
    if not k: sys.exit("DASH_KEY is not set")
    return base64.b64decode(k)


def dec(path, k):
    o = json.load(open(path))
    return json.loads(AESGCM(k).decrypt(base64.b64decode(o["iv"]), base64.b64decode(o["ct"]), AAD))


def enc(obj, k):
    iv = os.urandom(12)
    ct = AESGCM(k).encrypt(iv, json.dumps(obj, separators=(",", ":")).encode(), AAD)
    return {"v": 1, "iv": base64.b64encode(iv).decode(), "ct": base64.b64encode(ct).decode()}


def get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    return json.load(urllib.request.urlopen(req, timeout=25))


def fetch(s):
    """(price, label, previous close or previous NAV)."""
    if s["src"] == "yahoo":
        m = get("https://query1.finance.yahoo.com/v8/finance/chart/%s?range=1d&interval=1d" % urllib.parse.quote(s["sym"]))["chart"]["result"][0]["meta"]
        pc = m.get("chartPreviousClose") or m.get("previousClose")
        return float(m["regularMarketPrice"]), dt.datetime.fromtimestamp(m["regularMarketTime"], IST).strftime("%d %b %H:%M IST"), (float(pc) if pc else None)
    data = get("https://api.mfapi.in/mf/%s" % s["code"])["data"]
    d = data[0]
    return float(d["nav"]), "NAV " + dt.datetime.strptime(d["date"], "%d-%m-%Y").strftime("%d %b"), (float(data[1]["nav"]) if len(data) > 1 else None)


def main():
    k = key()
    syms = dec(SYMBOLS, k)
    os.makedirs(OUT, exist_ok=True)
    old_path = os.path.join(OUT, "prices.enc")
    old = dec(old_path, k)["prices"] if os.path.exists(old_path) else {}
    prices, failed = dict(old), []
    for key_, s in syms.items():
        for attempt in range(3):
            try:
                p, at, pc = fetch(s); prices[key_] = {"p": p, "at": at, "pc": pc}; break
            except Exception as e:
                if attempt == 2: failed.append(type(e).__name__)   # no symbols in logs or status
                time.sleep(2)
    now = dt.datetime.now(IST).isoformat(timespec="seconds")
    json.dump(enc({"at": now, "source": "actions", "prices": prices}, k), open(old_path, "w"))
    st_path = os.path.join(OUT, "status.json")
    st = json.load(open(st_path)) if os.path.exists(st_path) else {}
    st.update(prices_at=now, prices_ok=len(syms) - len(failed), prices_failed=len(failed), prices_errors=failed[:10])
    json.dump(st, open(st_path, "w"), indent=1)
    print("prices: %d ok, %d failed" % (len(syms) - len(failed), len(failed)))   # counts only
    if len(failed) > len(syms) / 2: sys.exit(1)


if __name__ == "__main__":
    main()
