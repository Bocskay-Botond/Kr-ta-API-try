// Kréta API kapcsolat-teszt — egyfájlos helyi proxy szerver.
// Futtatás:  node server.js    majd nyisd meg:  http://localhost:3000
// Követelmény: Node.js 18+ (beépített fetch + crypto, nincs npm install).

const http = require('node:http');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const PORT = 3000;

// A Kréta IDP-be hardcodeolt HMAC kulcs (ASCII "5Kmpmgd5fJ").
const HMAC_KEY = Buffer.from([53, 75, 109, 112, 109, 103, 100, 53, 102, 74]);
const IDP = 'https://idp.e-kreta.hu';
const UA = 'hu.ekreta.student/1.0.5/Android/0/0';

// Több login-stratégia: az első, ami 200-at + access_token-t ad, nyer.
// Az e-Kréta idővel váltogatta ezeket, ezért próbálunk többfélét.
const STRATEGIES = [
  { ver: 'v2', hash: 'sha512', userField: 'userName', clientId: 'kreta-ellenorzo-mobile-android' },
  { ver: 'v1', hash: 'sha512', userField: 'userName', clientId: 'kreta-ellenorzo-mobile-android' },
  { ver: 'v2', hash: 'sha512', userField: 'username', clientId: 'kreta-ellenorzo-mobile' },
  { ver: 'v1', hash: 'sha256', userField: 'username', clientId: 'kreta-ellenorzo-mobile' },
];

async function getNonce() {
  const r = await fetch(IDP + '/nonce', { headers: { 'User-Agent': UA } });
  if (!r.ok) throw new Error('nonce lekérés sikertelen: HTTP ' + r.status);
  return (await r.text()).trim();
}

function sign(username, institute, nonce, hash) {
  const msg = (username.toLowerCase() + institute.toLowerCase() + nonce);
  return crypto.createHmac(hash, HMAC_KEY).update(msg, 'utf8').digest('base64');
}

async function tryLogin(institute, username, password, s, log) {
  const nonce = await getNonce(); // friss nonce minden próbához (egyszer használatos lehet)
  const key = sign(username, institute, nonce, s.hash);

  const body = new URLSearchParams();
  body.set(s.userField, username);
  body.set('password', password);
  body.set('institute_code', institute);
  body.set('grant_type', 'password');
  body.set('client_id', s.clientId);

  const tag = `${s.ver}/${s.hash}/${s.userField}/${s.clientId}`;
  log.push(`→ próba: ${tag}`);

  const r = await fetch(IDP + '/connect/token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8',
      'User-Agent': UA,
      'X-AuthorizationPolicy-Key': key,
      'X-AuthorizationPolicy-Version': s.ver,
      'X-AuthorizationPolicy-Nonce': nonce,
    },
    body: body.toString(),
  });

  const text = await r.text();
  let json = {};
  try { json = JSON.parse(text); } catch (_) {}

  if (r.ok && json.access_token) {
    log.push(`✓ siker (HTTP ${r.status}) — ${tag}`);
    return { token: json, strategy: tag };
  }
  const reason = json.error || json.error_description || ('HTTP ' + r.status);
  log.push(`✗ elutasítva: ${reason}`);
  return null;
}

async function getJson(institute, token, endpoint) {
  const r = await fetch(`https://${institute}.e-kreta.hu/ellenorzo/V3/Sajat/${endpoint}`, {
    headers: { 'Authorization': 'Bearer ' + token, 'User-Agent': UA, 'Accept': 'application/json' },
  });
  if (!r.ok) return null;
  try { return await r.json(); } catch (_) { return null; }
}

async function runTest({ institute, username, password }) {
  const log = [];
  let result = null;
  for (const s of STRATEGIES) {
    try {
      result = await tryLogin(institute, username, password, s, log);
      if (result) break;
    } catch (e) {
      log.push(`✗ hiba: ${e.message}`);
    }
  }

  if (!result) {
    return { ok: false, error: 'Egyik login-stratégia sem ment át. Ellenőrizd az intézménykódot / OM-azonosítót / jelszót.', log };
  }

  const token = result.token.access_token;
  log.push('→ adatok lekérése a tokennel…');

  const student = await getJson(institute, token, 'TanuloAdatlap');
  const grades = await getJson(institute, token, 'Ertekelesek');

  if (student) log.push('✓ TanuloAdatlap OK');
  if (Array.isArray(grades)) log.push(`✓ Ertekelesek OK (${grades.length} db)`);

  const sample = Array.isArray(grades)
    ? grades.slice(-5).reverse().map(g => ({
        subject: g.Tantargy?.Nev || '—',
        value: (g.SzamErtek ? g.SzamErtek : (g.SzovegesErtek || '—')),
        date: (g.KeszitesDatuma || '').slice(0, 10),
      }))
    : [];

  return {
    ok: true,
    strategy: result.strategy,
    expiresIn: result.token.expires_in,
    studentName: student?.Nev || null,
    instituteName: student?.IntezmenyNev || null,
    gradeCount: Array.isArray(grades) ? grades.length : 0,
    grades: sample,
    log,
  };
}

async function getInstitutes() {
  const r = await fetch('https://kretaglobalmobileapi2.ekreta.hu/api/v3/Institute', {
    headers: { 'apiKey': '7856d350-1fda-45f5-822d-e1a2f3f1acf0', 'User-Agent': UA, 'Accept': 'application/json' },
  });
  if (!r.ok) throw new Error('iskolalista HTTP ' + r.status);
  const data = await r.json();
  return data.map(i => ({ instituteCode: i.instituteCode, name: i.name, city: i.city }));
}

function readBody(req) {
  return new Promise((res, rej) => {
    let b = '';
    req.on('data', c => { b += c; if (b.length > 1e6) req.destroy(); });
    req.on('end', () => res(b));
    req.on('error', rej);
  });
}

const server = http.createServer(async (req, res) => {
  try {
    if (req.method === 'GET' && (req.url === '/' || req.url === '/index.html')) {
      const html = fs.readFileSync(path.join(__dirname, 'public', 'index.html'));
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(html);
    }

    if (req.method === 'GET' && req.url === '/api/institutes') {
      const list = await getInstitutes();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify(list));
    }

    if (req.method === 'POST' && req.url === '/api/test') {
      const body = JSON.parse(await readBody(req) || '{}');
      const out = await runTest(body);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify(out));
    }

    res.writeHead(404); res.end('Not found');
  } catch (e) {
    res.writeHead(500, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: false, error: e.message }));
  }
});

server.listen(PORT, () => {
  console.log(`\n  Kréta API teszt fut:  http://localhost:${PORT}\n  (leállítás: Ctrl+C)\n`);
});

      
