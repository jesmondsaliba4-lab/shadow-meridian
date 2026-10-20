# tpn-login (login.tpnintel.com)

Reserved-access hub behind Cloudflare Access.

- `backup-d766397e/` — exact code and settings of version d766397e (deployed 17 Oct 2026), saved 20 Oct 2026 before any change.
- `index.js` — current code (20 Oct 2026): adds the SHaiPING Malta tile and a National Workplace Index card showing only the current release ID, status and dates (no figures), read live from `shaipingmalta.tpnintel.com/data/index-current.json`.

Secrets (not in this repo): `SHAIPING_CLIENT_ID`, `SHAIPING_CLIENT_SECRET` — Access service token "TPN Intel hub — SHaiPING release reader" (expires 20 Oct 2027), allowed by policy "SHaiPING Malta — hub release reader (Service Auth)" on the SHaiPING Malta Access app. If it expires the card shows "Release information unavailable".
