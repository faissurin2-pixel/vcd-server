'use strict';
// ============================================================================
//  VICE CITY DRIFT — game server
//  * serves the game page (gzip/brotli) so friends only need a link
//  * accounts: register / login (scrypt-hashed passwords, token sessions)
//  * saves each player's profile (money, weapons, armor, stats)
//  * WebSocket room: relays player/vehicle state in ~15 Hz snapshots, chat,
//    gunfire, validated PvP hits, kill feed, shared time-of-day + weather
//  Run:  npm install  &&  node server.js        (see README.md)
// ============================================================================
const http = require('http'), fs = require('fs'), path = require('path'), zlib = require('zlib'), crypto = require('crypto'), readline = require('readline');
const { WebSocketServer } = require('ws');

// ---------------------------------------------------------------- config
function readJson(f) { try { return JSON.parse(fs.readFileSync(f, 'utf8')); } catch (e) { return {}; } }
const cfg = Object.assign({
  port: 8080, host: '0.0.0.0', serverName: 'VICE CITY DRIFT', maxPlayers: 16, tickHz: 15,
  gameFile: '', dataDir: path.join(__dirname, 'data'), allowRegister: true, admins: [], trustProxy: false,
  daySec: 1200, startHour: 17.2, registerPerHourPerIp: 6, badWords: [], spawnProtectSec: 3, sessionDays: 14,
}, readJson(path.join(__dirname, 'config.json')));
if (process.env.PORT) cfg.port = +process.env.PORT; if (process.env.MAX_PLAYERS) cfg.maxPlayers = +process.env.MAX_PLAYERS; if (process.env.GAME_FILE) cfg.gameFile = process.env.GAME_FILE;
const GAME_CANDIDATES = [cfg.gameFile, path.join(__dirname, 'public', 'index.html'), path.join(__dirname, '..', 'dist', 'game.html')].filter(Boolean);
const gamePath = GAME_CANDIDATES.find(f => { try { return fs.statSync(f).isFile(); } catch (e) { return false; } });
fs.mkdirSync(cfg.dataDir, { recursive: true });
const log = (...a) => console.log(new Date().toISOString().slice(11, 19), ...a);

// ---------------------------------------------------------------- utilities
const clamp = (v, a, b) => v < a ? a : v > b ? b : v;
const num = (v, d = 0) => (typeof v === 'number' && isFinite(v)) ? v : d;
const WEAPONS = { fists: { max: 45, range: 4 }, bat: { max: 110, range: 5 }, pistol: { max: 95, range: 110 }, smg: { max: 60, range: 100 }, shotgun: { max: 60, range: 55 }, rifle: { max: 75, range: 160 }, car: { max: 160, range: 20 }, expl: { max: 220, range: 40 } };
const NAME_RE = /^[\p{L}\p{N}_\-]{3,16}$/u;
function ipOf(req) { if (cfg.trustProxy && req.headers['x-forwarded-for']) return String(req.headers['x-forwarded-for']).split(',')[0].trim(); return (req.socket.remoteAddress || '').replace('::ffff:', ''); }
function cleanText(s, n) { return String(s == null ? '' : s).replace(/[\u0000-\u001f\u007f​-‏‪-‮⁦-⁩]/g, '').replace(/\s+/g, ' ').trim().slice(0, n); }
function filterBad(s) { if (!cfg.badWords.length) return s; let o = s; for (const w of cfg.badWords) { if (!w) continue; o = o.replace(new RegExp(w.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi'), m => '*'.repeat(m.length)); } return o; }

// ---------------------------------------------------------------- account store (JSON file, atomic writes)
const DEFAULT_PROFILE = () => ({ money: 2500, weapons: { pistol: [12, 72] }, cur: 'fists', armor: 0, packages: 0, missions: 0, kills: 0, pvpKills: 0, pvpDeaths: 0, playSec: 0, pos: null });
const Store = {
  file: path.join(cfg.dataDir, 'accounts.json'), db: { users: {} }, dirty: false,
  load() { try { this.db = JSON.parse(fs.readFileSync(this.file, 'utf8')); if (!this.db.users) this.db.users = {}; } catch (e) { if (fs.existsSync(this.file)) { fs.copyFileSync(this.file, this.file + '.corrupt-' + Date.now()); log('! accounts.json unreadable, backup kept'); } } },
  flush() { if (!this.dirty) return; this.dirty = false; const tmp = this.file + '.tmp'; try { fs.writeFileSync(tmp, JSON.stringify(this.db)); fs.renameSync(tmp, this.file); } catch (e) { log('! save failed', e.message); this.dirty = true; } },
  get(name) { return this.db.users[String(name).toLowerCase()]; },
  mark() { this.dirty = true; },
};
Store.load(); setInterval(() => Store.flush(), 4000).unref();
function hashPw(pw, salt) { return crypto.scryptSync(pw, salt, 64, { N: 16384, r: 8, p: 1 }); }
function makeUser(name, pw) { const salt = crypto.randomBytes(16); return { name, salt: salt.toString('hex'), hash: hashPw(pw, salt).toString('hex'), created: Date.now(), lastLogin: 0, profile: DEFAULT_PROFILE(), bank: { t: Date.now(), tokens: 60000 }, sus: 0 }; }
function checkPw(u, pw) { try { const h = hashPw(pw, Buffer.from(u.salt, 'hex')), x = Buffer.from(u.hash, 'hex'); return h.length === x.length && crypto.timingSafeEqual(h, x); } catch (e) { return false; } }

// profile validation: the client reports its progress, the server sanity-checks it (money can only rise at a plausible rate)
function sanitizeProfile(u, p) {
  const old = u.profile, out = Object.assign({}, old); if (!p || typeof p !== 'object') return old;
  const now = Date.now(), b = u.bank || (u.bank = { t: now, tokens: 60000 }); b.tokens = Math.min(120000, b.tokens + (now - b.t) / 1000 * 900); b.t = now; // allowance: $900/s, up to $120k banked
  if (typeof p.money === 'number' && isFinite(p.money)) { let m = clamp(Math.floor(p.money), 0, 99999999); const gain = m - old.money; if (gain > 0) { const ok = Math.min(gain, Math.floor(b.tokens)); b.tokens -= ok; if (ok < gain) { u.sus = (u.sus || 0) + 1; log('! money clamp for', u.name, '+' + gain, '->', ok); } m = old.money + ok; } out.money = m; }
  if (p.weapons && typeof p.weapons === 'object') { const w = {}; for (const k of Object.keys(p.weapons)) { if (!WEAPONS[k] || k === 'fists' || k === 'car' || k === 'expl') continue; const a = p.weapons[k]; if (!Array.isArray(a)) continue; w[k] = [clamp(Math.floor(num(a[0])), 0, 99), clamp(Math.floor(num(a[1])), 0, 500)]; } out.weapons = w; }
  if (typeof p.cur === 'string' && (p.cur === 'fists' || out.weapons[p.cur])) out.cur = p.cur;
  out.armor = clamp(Math.round(num(p.armor, old.armor)), 0, 100);
  out.packages = clamp(Math.floor(num(p.packages, old.packages)), 0, 999); out.missions = clamp(Math.floor(num(p.missions, old.missions)), 0, 99999); out.kills = clamp(Math.floor(num(p.kills, old.kills)), 0, 9999999);
  if (Array.isArray(p.pos) && p.pos.length === 2 && isFinite(p.pos[0]) && isFinite(p.pos[1]) && Math.abs(p.pos[0]) < 2500 && Math.abs(p.pos[1]) < 2500) out.pos = [Math.round(p.pos[0] * 10) / 10, Math.round(p.pos[1] * 10) / 10];
  u.profile = out; Store.mark(); return out;
}

// ---------------------------------------------------------------- sessions + brute-force throttles
const sessions = new Map(); // token -> {user(key), exp}
function newSession(key) { const t = crypto.randomBytes(24).toString('hex'); sessions.set(t, { key, exp: Date.now() + cfg.sessionDays * 864e5 }); return t; }
setInterval(() => { const n = Date.now(); for (const [t, s] of sessions) if (s.exp < n) sessions.delete(t); }, 60000).unref();
const throttle = new Map(); // key -> {n, t, lock}
function tooMany(key) { const r = throttle.get(key); return r && r.lock > Date.now(); }
function fail(key, limit = 6, lockMs = 90000) { const n = Date.now(); let r = throttle.get(key); if (!r || n - r.t > 600000) r = { n: 0, t: n, lock: 0 }; r.n++; if (r.n >= limit) { r.lock = n + lockMs; r.n = 0; r.t = n; } throttle.set(key, r); }
const regLog = new Map(); // ip -> [timestamps]
setInterval(() => { const n = Date.now(); for (const [k, r] of throttle) if (n - r.t > 900000 && r.lock < n) throttle.delete(k); for (const [k, a] of regLog) { const f = a.filter(t => n - t < 36e5); if (f.length) regLog.set(k, f); else regLog.delete(k); } }, 120000).unref();

// ---------------------------------------------------------------- HTTP: game page + JSON API
const files = {}; // cached compressed game page
function loadGame() {
  if (!gamePath) { log('! no game file found (put game.html in server/public/index.html)'); return; }
  const raw = fs.readFileSync(gamePath), st = fs.statSync(gamePath); files.etag = '"' + st.size.toString(36) + '-' + Math.floor(st.mtimeMs).toString(36) + '"'; files.raw = raw;
  zlib.gzip(raw, { level: 6 }, (e, b) => { if (!e) { files.gz = b; log('game page gzip ready:', (b.length / 1048576).toFixed(1), 'MB (raw ' + (raw.length / 1048576).toFixed(1) + ' MB)'); } });
  zlib.brotliCompress(raw, { params: { [zlib.constants.BROTLI_PARAM_QUALITY]: 6, [zlib.constants.BROTLI_PARAM_SIZE_HINT]: raw.length } }, (e, b) => { if (!e) { files.br = b; log('game page brotli ready:', (b.length / 1048576).toFixed(1), 'MB'); } });
}
loadGame();
function readBody(req, cb) { let s = '', done = false; req.on('data', c => { s += c; if (s.length > 2048 && !done) { done = true; req.destroy(); } }); req.on('end', () => { if (done) return; try { cb(JSON.parse(s || '{}')); } catch (e) { cb(null); } }); }
function json(res, code, obj) { const b = JSON.stringify(obj); res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Access-Control-Allow-Origin': '*', 'Cache-Control': 'no-store' }); res.end(b); }
function profileOut(u) { return Object.assign({}, u.profile); }
const online = new Map(); // account key -> client
const server = http.createServer((req, res) => {
  const url = (req.url || '/').split('?')[0];
  if (req.method === 'OPTIONS') { res.writeHead(204, { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET,POST', 'Access-Control-Allow-Headers': 'Content-Type', 'Access-Control-Max-Age': '600' }); return res.end(); }
  if ((req.method === 'GET' || req.method === 'HEAD') && (url === '/' || url === '/index.html' || url === '/game.html')) {
    if (!files.raw) { res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }); return res.end('game file not found on the server'); }
    const ae = String(req.headers['accept-encoding'] || ''), h = { 'Content-Type': 'text/html; charset=utf-8', 'ETag': files.etag, 'Cache-Control': 'no-cache', 'Vary': 'Accept-Encoding' };
    if (req.headers['if-none-match'] === files.etag) { res.writeHead(304, h); return res.end(); }
    let body = files.raw; if (/\bbr\b/.test(ae) && files.br) { h['Content-Encoding'] = 'br'; body = files.br; } else if (/\bgzip\b/.test(ae) && files.gz) { h['Content-Encoding'] = 'gzip'; body = files.gz; }
    h['Content-Length'] = body.length; res.writeHead(200, h); return res.end(req.method === 'HEAD' ? undefined : body);
  }
  if (url === '/favicon.ico') { res.writeHead(204); return res.end(); }
  if (req.method === 'GET' && url === '/api/status') return json(res, 200, { ok: true, name: cfg.serverName, players: clients.size, max: cfg.maxPlayers, register: cfg.allowRegister });
  if (req.method === 'POST' && (url === '/api/login' || url === '/api/register')) {
    const ip = ipOf(req), reg = url === '/api/register';
    return readBody(req, b => {
      if (!b || typeof b.user !== 'string' || typeof b.pass !== 'string') return json(res, 400, { ok: false, err: 'bad request' });
      const name = cleanText(b.user, 16), pass = b.pass.slice(0, 64), key = name.toLowerCase();
      if (tooMany('ip:' + ip) || tooMany('u:' + key)) return json(res, 429, { ok: false, err: 'ลองผิดบ่อยเกินไป รอสักครู่แล้วลองใหม่' });
      if (reg) {
        if (!cfg.allowRegister) return json(res, 403, { ok: false, err: 'เซิร์ฟเวอร์นี้ปิดรับสมัครใหม่' });
        if (!NAME_RE.test(name)) return json(res, 400, { ok: false, err: 'ชื่อผู้ใช้ต้องยาว 3-16 ตัว (ตัวอักษร/ตัวเลข/_/-)' });
        if (pass.length < 6) return json(res, 400, { ok: false, err: 'รหัสผ่านต้องยาวอย่างน้อย 6 ตัว' });
        if (Store.get(name)) return json(res, 409, { ok: false, err: 'ชื่อนี้ถูกใช้แล้ว' });
        const arr = (regLog.get(ip) || []).filter(t => Date.now() - t < 36e5); if (arr.length >= cfg.registerPerHourPerIp) return json(res, 429, { ok: false, err: 'สมัครจาก IP นี้บ่อยเกินไป' }); arr.push(Date.now()); regLog.set(ip, arr);
        const u = makeUser(name, pass); u.lastLogin = Date.now(); Store.db.users[key] = u; Store.mark(); Store.flush(); log('+ new account', name);
        return json(res, 200, { ok: true, token: newSession(key), name: u.name, profile: profileOut(u), isNew: true });
      }
      const u = Store.get(name); if (!u || !checkPw(u, pass)) { fail('ip:' + ip); fail('u:' + key); return json(res, 401, { ok: false, err: 'ชื่อหรือรหัสผ่านไม่ถูกต้อง' }); }
      if (u.banned) return json(res, 403, { ok: false, err: 'บัญชีนี้ถูกระงับ' });
      u.lastLogin = Date.now(); Store.mark(); return json(res, 200, { ok: true, token: newSession(key), name: u.name, profile: profileOut(u) });
    });
  }
  res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }); res.end('not found');
});

// ---------------------------------------------------------------- realtime room
const wss = new WebSocketServer({ noServer: true, maxPayload: 4096, perMessageDeflate: false });
const clients = new Map(); let nextId = 1;
const world = { t0: Date.now(), hour0: cfg.startHour, rain: 0, rainTarget: 0, nextWeather: Date.now() + 120000, hourOverride: null };
function worldHour() { return (world.hour0 + (Date.now() - world.t0) / 1000 * 24 / cfg.daySec) % 24; }
function setHour(h) { world.hour0 = h; world.t0 = Date.now(); }
function worldMsg() { return JSON.stringify({ t: 'world', h: +worldHour().toFixed(3), rain: world.rainTarget }); }
function send(c, o) { if (c.ws.readyState === 1) { try { c.ws.send(typeof o === 'string' ? o : JSON.stringify(o)); } catch (e) { } } }
function bcast(o, except) { const s = typeof o === 'string' ? o : JSON.stringify(o); for (const c of clients.values()) if (c !== except) send(c, s); }
function sys(text, to) { const m = { t: 'chat', id: 0, name: '', m: text, sys: 1 }; if (to) send(to, m); else bcast(m); }
function pub(c) { return { id: c.id, name: c.name, k: c.u.profile.pvpKills, d: c.u.profile.pvpDeaths, ping: c.ping | 0 }; }
function byName(n) { n = String(n).toLowerCase(); for (const c of clients.values()) if (c.name.toLowerCase() === n) return c; return null; }

server.on('upgrade', (req, sock, head) => {
  const q = new URL(req.url, 'http://x'); if (q.pathname !== '/ws') { sock.destroy(); return; }
  const s = sessions.get(q.searchParams.get('token') || ''); const u = s && s.exp > Date.now() ? Store.db.users[s.key] : null;
  wss.handleUpgrade(req, sock, head, ws => {
    if (!u) { ws.send(JSON.stringify({ t: 'err', code: 'auth', m: 'เซสชันหมดอายุ กรุณาเข้าสู่ระบบใหม่' })); return ws.close(); }
    if (u.banned) { ws.send(JSON.stringify({ t: 'err', code: 'ban', m: 'บัญชีนี้ถูกระงับ' })); return ws.close(); }
    const key = u.name.toLowerCase(); const prev = online.get(key); if (prev) { send(prev, { t: 'err', code: 'dup', m: 'มีการเข้าสู่ระบบบัญชีนี้จากที่อื่น' }); prev.ws.close(); removeClient(prev); }
    if (clients.size >= cfg.maxPlayers) { ws.send(JSON.stringify({ t: 'err', code: 'full', m: 'เซิร์ฟเวอร์เต็ม (' + cfg.maxPlayers + ' คน)' })); return ws.close(); }
    addClient(ws, u, key, ipOf(req));
  });
});
function addClient(ws, u, key, ip) {
  const c = { id: nextId++, ws, u, key, name: u.name, ip, st: null, car: null, alive: true, protUntil: Date.now() + cfg.spawnProtectSec * 1000, ping: 0, pgN: 0, pgT: 0, bucket: 200, bt: Date.now(), lastChat: 0, chatN: [], lastFire: 0, hitBank: 40, hitT: Date.now(), lastHurtBy: null, lastSave: 0, joined: Date.now(), muted: false, dirty: false, lastSeen: Date.now() };
  clients.set(c.id, c); online.set(key, c);
  send(c, { t: 'welcome', id: c.id, name: c.name, profile: profileOut(u), server: { name: cfg.serverName, max: cfg.maxPlayers, hz: cfg.tickHz, daySec: cfg.daySec }, players: [...clients.values()].filter(o => o !== c).map(pub), world: { h: +worldHour().toFixed(3), rain: world.rainTarget } });
  rosterDirty = true; bcast({ t: 'join', p: pub(c) }, c); sys('➜ ' + c.name + ' เข้าร่วมเกม'); log('+ join', c.name, '(' + clients.size + ')');
  ws.on('message', (d, bin) => { if (bin) return; onMessage(c, d); });
  ws.on('close', () => removeClient(c)); ws.on('error', () => { });
  c.lastPong = Date.now(); ws.on('pong', () => { c.lastPong = Date.now(); }); // a browser tab that is busy (shader compile, loading) can stall for seconds, so be tolerant
}
function removeClient(c) {
  if (!clients.has(c.id)) return; clients.delete(c.id); if (online.get(c.key) === c) online.delete(c.key); c.u.profile.playSec += Math.round((Date.now() - c.joined) / 1000); Store.mark(); Store.flush();
  bcast({ t: 'leave', id: c.id }); sys('✕ ' + c.name + ' ออกจากเกม'); log('- leave', c.name, '(' + clients.size + ')');
}
function finite(a, n) { if (!Array.isArray(a) || a.length < n || a.length > 24) return false; for (let i = 0; i < n; i++) if (typeof a[i] !== 'number' || !isFinite(a[i])) return false; return true; }
function onMessage(c, raw) {
  const now = Date.now(); c.bucket = Math.min(240, c.bucket + (now - c.bt) / 1000 * 120); c.bt = now; if (--c.bucket < 0) { if (c.bucket < -200) { send(c, { t: 'err', code: 'flood', m: 'ส่งข้อมูลถี่เกินไป' }); c.ws.close(); } return; }
  let m; try { m = JSON.parse(raw); } catch (e) { return; } if (!m || typeof m.t !== 'string') return; c.lastSeen = now;
  switch (m.t) {
    case 's': { // player (+ optional vehicle) state
      if (!finite(m.p, 9)) return; const p = m.p; if (Math.abs(p[0]) > 3000 || Math.abs(p[2]) > 3000) return;
      const st = { p: p.slice(0, 9).map(v => Math.round(v * 100) / 100), w: typeof m.w === 'string' && WEAPONS[m.w] ? m.w : 'fists' }; st.f = p[9] | 0;
      if (Array.isArray(m.c) && m.c.length >= 14 && typeof m.c[0] === 'string' && m.c[0].length < 24 && finite(m.c.slice(1), 13)) { const k = m.c.slice(); k[0] = cleanText(k[0], 20); st.c = k; c.car = k[2]; } else c.car = null;
      const wasAlive = c.alive; c.alive = !(st.f & 4); if (!wasAlive && c.alive) c.protUntil = now + cfg.spawnProtectSec * 1000;
      c.st = st; c.dirty = true; break;
    }
    case 'chat': {
      let text = cleanText(m.m, 140); if (!text) return; if (c.muted) return sys('คุณถูกปิดแชต', c);
      c.chatN = c.chatN.filter(t => now - t < 10000); if (now - c.lastChat < 600 || c.chatN.length >= 8) return sys('พิมพ์ช้าลงหน่อย', c); c.lastChat = now; c.chatN.push(now);
      if (text[0] === '/') return command(c, text);
      bcast({ t: 'chat', id: c.id, name: c.name, m: filterBad(text) }); break;
    }
    case 'fire': { // gunshot / melee swing, shown to everybody else
      const w = WEAPONS[m.w] && m.w !== 'car' && m.w !== 'expl' ? m.w : null; if (!w || !c.alive) return; if (now - c.lastFire < 40) return; c.lastFire = now;
      const o = { t: 'fire', id: c.id, w }; if (finite(m.o, 3) && finite(m.d, 3)) { o.o = m.o.slice(0, 3).map(v => Math.round(v * 100) / 100); o.d = m.d.slice(0, 3).map(v => Math.round(v * 1000) / 1000); } bcast(o, c); break;
    }
    case 'hit': { // shooter-reported damage on another player, plausibility-checked then forwarded to the victim
      const v = clients.get(m.v | 0); if (!v || v === c || !c.alive || !v.alive || !c.st || !v.st) return; const wk = WEAPONS[m.w] ? m.w : null; if (!wk) return; const W = WEAPONS[wk];
      const d = clamp(num(m.d), 0, W.max); if (d <= 0) return; const dx = c.st.p[0] - v.st.p[0], dz = c.st.p[2] - v.st.p[2]; if (Math.hypot(dx, dz) > W.range + 25) return;
      c.hitBank = Math.min(40, c.hitBank + (now - c.hitT) / 1000 * 30); c.hitT = now; if (--c.hitBank < 0) return; if (now < v.protUntil) return;
      v.lastHurtBy = { id: c.id, w: wk, t: now }; send(v, { t: 'hurt', from: c.id, d, h: m.h ? 1 : 0, w: wk }); break;
    }
    case 'hitcar': { // damage dealt to a car driven by another player -> forwarded to that car's owner
      const v = clients.get(m.v | 0); if (!v || v === c || !c.st || !v.st || !v.car) return; const d = clamp(num(m.d), 0, 60); if (d <= 0) return; if (Math.hypot(c.st.p[0] - v.st.p[0], c.st.p[2] - v.st.p[2]) > 200) return;
      v.lastHurtBy = { id: c.id, w: 'car', t: now }; send(v, { t: 'carhit', from: c.id, d }); break;
    }
    case 'died': {
      if (!c.alive && c.deadReported && now - c.deadReported < 2000) return; c.deadReported = now; c.alive = false;
      const lh = c.lastHurtBy && now - c.lastHurtBy.t < 9000 ? c.lastHurtBy : null, k = lh ? clients.get(lh.id) : null; c.lastHurtBy = null;
      c.u.profile.pvpDeaths++; if (k && k !== c) k.u.profile.pvpKills++; Store.mark();
      bcast({ t: 'kill', k: k ? k.id : 0, v: c.id, w: lh ? lh.w : (m.w === 'wasted' ? 'wasted' : ''), kk: k ? k.u.profile.pvpKills : 0, vd: c.u.profile.pvpDeaths }); break;
    }
    case 'save': { if (now - c.lastSave < 2000) return; c.lastSave = now; sanitizeProfile(c.u, m.p); break; }
    case 'pg': { if (m.n === c.pgN && c.pgT) { c.ping = Math.round(now - c.pgT); c.pgT = 0; } break; }
    case 'bye': { c.ws.close(); break; }
  }
}
function command(c, text) {
  const [cmd, ...rest] = text.slice(1).split(' '), arg = rest.join(' ').trim(), isAdmin = cfg.admins.map(s => s.toLowerCase()).includes(c.name.toLowerCase());
  switch (cmd.toLowerCase()) {
    case 'w': case 'msg': { const sp = arg.indexOf(' '); if (sp < 0) return sys('ใช้: /w ชื่อ ข้อความ', c); const t = byName(arg.slice(0, sp)); if (!t) return sys('ไม่พบผู้เล่นชื่อนั้น', c); const m = filterBad(cleanText(arg.slice(sp + 1), 140)); send(t, { t: 'chat', id: c.id, name: c.name, m, to: 1 }); send(c, { t: 'chat', id: c.id, name: c.name, m, to: 2, toName: t.name }); return; }
    case 'players': case 'list': return sys('ออนไลน์ ' + clients.size + '/' + cfg.maxPlayers + ': ' + [...clients.values()].map(o => o.name).join(', '), c);
    case 'help': return sys('คำสั่ง: /w ชื่อ ข้อความ · /players · ' + (isAdmin ? '/kick ชื่อ · /mute ชื่อ · /unmute ชื่อ · /say ข้อความ · /time 0-24 · /rain 0-1' : 'Tab = รายชื่อผู้เล่น'), c);
  }
  if (!isAdmin) return sys('ไม่รู้จักคำสั่ง (พิมพ์ /help)', c);
  switch (cmd.toLowerCase()) {
    case 'kick': { const t = byName(arg); if (!t) return sys('ไม่พบผู้เล่น', c); send(t, { t: 'err', code: 'kick', m: 'คุณถูกเตะออกจากเซิร์ฟเวอร์' }); t.ws.close(); return sys(t.name + ' ถูกเตะ'); }
    case 'mute': case 'unmute': { const t = byName(arg); if (!t) return sys('ไม่พบผู้เล่น', c); t.muted = cmd.toLowerCase() === 'mute'; return sys(t.name + (t.muted ? ' ถูกปิดแชต' : ' เปิดแชตแล้ว'), c); }
    case 'say': return sys('📢 ' + arg);
    case 'time': { const h = parseFloat(arg); if (isFinite(h)) { setHour(((h % 24) + 24) % 24); bcast(worldMsg()); } return; }
    case 'rain': { const r = clamp(parseFloat(arg) || 0, 0, 1); world.rainTarget = r; world.nextWeather = Date.now() + 240000; bcast(worldMsg()); return; }
  }
  sys('ไม่รู้จักคำสั่ง (พิมพ์ /help)', c);
}

// ---------------------------------------------------------------- tick: snapshots, ping, world clock, weather
let tickN = 0, secN = 0, rosterDirty = false;
setInterval(() => {
  tickN++; const arr = []; for (const c of clients.values()) if (c.st && c.dirty) { const s = c.st, o = [c.id].concat(s.p); o.push(s.f, s.w); if (s.c) o.push(s.c); arr.push(o); c.dirty = false; c.snapped = true; }
  if (arr.length) { const msg = JSON.stringify({ t: 'snap', p: arr }); for (const c of clients.values()) { if (arr.length === 1 && arr[0][0] === c.id) continue; send(c, msg); } } // the receiver ignores its own entry
}, Math.round(1000 / cfg.tickHz));
setInterval(() => { // 1 Hz: ping probes, idle kick, weather
  const now = Date.now();
  for (const c of clients.values()) { if (now - c.lastSeen > 45000) { send(c, { t: 'err', code: 'idle', m: 'หมดเวลาการเชื่อมต่อ' }); c.ws.close(); continue; } if (now - c.lastPong > 30000) { c.ws.terminate(); continue; } try { c.ws.ping(); } catch (e) { } c.pgN = (c.pgN + 1) & 0xffff; c.pgT = now; send(c, { t: 'pg', n: c.pgN }); }
  if (now > world.nextWeather) { world.rainTarget = world.rainTarget > 0.1 ? 0 : (Math.random() < 0.45 ? +(0.5 + Math.random() * 0.5).toFixed(2) : 0); world.nextWeather = now + 110000 + Math.random() * 150000; bcast(worldMsg()); }
  secN++; if (secN % 10 === 0) bcast(worldMsg()); if (secN % 3 === 0 || rosterDirty) { rosterDirty = false; bcast({ t: 'roster', p: [...clients.values()].map(pub) }); }
}, 1000).unref();

// ---------------------------------------------------------------- console (admin) + shutdown
if (process.stdin.isTTY) {
  const rl = readline.createInterface({ input: process.stdin });
  rl.on('line', line => {
    const [cmd, ...r] = line.trim().split(' '), arg = r.join(' ');
    if (cmd === 'list') { for (const c of clients.values()) console.log(c.id, c.name, c.ip, c.ping + 'ms'); }
    else if (cmd === 'kick') { const t = byName(arg); if (t) { send(t, { t: 'err', code: 'kick', m: 'คุณถูกเตะออกจากเซิร์ฟเวอร์' }); t.ws.close(); } }
    else if (cmd === 'say') sys('📢 ' + arg);
    else if (cmd === 'ban' || cmd === 'unban') { const u = Store.get(arg); if (u) { u.banned = cmd === 'ban'; Store.mark(); const t = byName(arg); if (t && u.banned) { send(t, { t: 'err', code: 'ban', m: 'บัญชีนี้ถูกระงับ' }); t.ws.close(); } console.log(cmd, u.name); } }
    else if (cmd === 'passwd') { const [n, p] = arg.split(' '); const u = Store.get(n || ''); if (u && p && p.length >= 6) { const salt = crypto.randomBytes(16); u.salt = salt.toString('hex'); u.hash = hashPw(p, salt).toString('hex'); Store.mark(); console.log('password changed for', u.name); } else console.log('usage: passwd <user> <newpassword(>=6)>'); }
    else if (cmd === 'save') { Store.mark(); Store.flush(); console.log('saved'); }
    else if (cmd === 'quit' || cmd === 'exit') shutdown();
    else console.log('commands: list | kick <name> | say <msg> | ban <name> | unban <name> | passwd <name> <pw> | save | quit');
  });
}
function shutdown() { log('saving & shutting down...'); for (const c of clients.values()) { try { c.ws.close(1001); } catch (e) { } } Store.mark(); Store.flush(); process.exit(0); }
process.on('SIGINT', shutdown); process.on('SIGTERM', shutdown);
process.on('uncaughtException', e => { console.error('uncaught', e); });

for (const n of cfg.admins) if (!Store.get(n)) log('! admin account "' + n + '" is not registered yet — register it FIRST, otherwise someone else could take that name');
server.listen(cfg.port, cfg.host, () => {
  log('============================================');
  log(' ' + cfg.serverName + '  —  up on port ' + cfg.port + '  (max ' + cfg.maxPlayers + ' players)');
  log(' game:  ' + (gamePath || 'NOT FOUND'));
  log(' open:  http://localhost:' + cfg.port + '   (friends on your network: http://<your-ip>:' + cfg.port + ')');
  log('============================================');
});
