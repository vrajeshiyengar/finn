# finn

Finn: a private, static money dashboard. Every data file in `data/` is AES-256-GCM ciphertext; the page decrypts
it in the browser only after the owner signs in with Google and the key is read from that account's
Drive app-data folder (scope `drive.appdata`). Nothing readable lives in this repository.

- `index.html`, `assets/` — the page (no third-party scripts except Google Identity Services).
- `data/*.enc` — encrypted data; `data/status.json` — timestamps and counts only.
- `scripts/prices.py` + `.github/workflows/prices.yml` — scheduled price refresh (key from an Actions secret).
