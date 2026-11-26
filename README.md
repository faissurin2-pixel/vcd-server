# VICE CITY DRIFT — online server
Node.js server (ws) that serves the game page (`public/index.html`), accounts, chat, PvP and the RP economy.

* Deploy on Render: `render.yaml` (free plan, accounts restored from a signed copy kept in each player's browser) or `render.paid.yaml` (Starter + persistent disk).
* Local run: `npm install && node server.js` then open http://localhost:8080
* Env: `PORT`, `DATA_DIR`, `TRUST_PROXY`, `VAULT_SECRET`, `SERVER_NAME`, `MAX_PLAYERS`, `ALLOW_REGISTER`, `ADMINS`.
* Admin: set `ADMIN_CODE` (>= 8 chars) in the service's Environment tab, then type `/admin <code>` in the in-game chat. Never commit the code to the repo.
