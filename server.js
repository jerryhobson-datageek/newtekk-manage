'use strict';
const http   = require('http');
const https  = require('https');
const tls    = require('tls');
const crypto = require('crypto');
const fs     = require('fs');
const path   = require('path');

// ── Config ───────────────────────────────────────────────────────────────────
let cfg = {};
const CFG_PATH = path.join(__dirname, 'config.json');
function loadConfig() { cfg = JSON.parse(fs.readFileSync(CFG_PATH, 'utf8')); }
loadConfig();
fs.watch(CFG_PATH, () => {
  try { loadConfig(); console.log('Config reloaded.'); }
  catch (e) { console.error('Config reload failed:', e.message); }
});

// ── Activity log ─────────────────────────────────────────────────────────────
const DATA_DIR       = path.join(__dirname, 'data');
const ACTIVITY_FILE  = path.join(DATA_DIR, 'activity.json');
const MAX_ACTIVITY   = 200;

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(ACTIVITY_FILE)) fs.writeFileSync(ACTIVITY_FILE, '[]');

function loadActivity() {
  try { return JSON.parse(fs.readFileSync(ACTIVITY_FILE, 'utf8')); }
  catch { return []; }
}

function logActivity(type, message, user) {
  const entries = loadActivity();
  entries.push({ type, message, user: user || null, ts: Date.now() });
  fs.writeFileSync(ACTIVITY_FILE, JSON.stringify(entries.slice(-MAX_ACTIVITY), null, 2));
}

// ── Helpers ──────────────────────────────────────────────────────────────────
function json(res, status, data) {
  const body = JSON.stringify(data);
  res.writeHead(status, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) });
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString();
      try { resolve(JSON.parse(raw || '{}')); } catch { resolve({}); }
    });
    req.on('error', reject);
  });
}

function httpsRequest(options, body) {
  return new Promise((resolve, reject) => {
    const req = https.request(options, res => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        const raw = Buffer.concat(chunks).toString();
        try { resolve({ status: res.statusCode, body: JSON.parse(raw) }); }
        catch { resolve({ status: res.statusCode, body: raw }); }
      });
    });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

async function verifyToken(token) {
  if (!token) return null;
  try {
    const u = new URL(cfg.authUrl + '/verify');
    const r = await httpsRequest({
      hostname: u.hostname, port: Number(u.port) || 443,
      path: u.pathname, method: 'GET',
      headers: { Authorization: `Bearer ${token}` }
    });
    return r.status === 200 ? r.body : null;
  } catch { return null; }
}

async function hostinger(method, apiPath, body) {
  const bodyStr = body ? JSON.stringify(body) : undefined;
  const headers = {
    Authorization: `Bearer ${cfg.hostingerToken}`,
    'Content-Type': 'application/json'
  };
  if (bodyStr) headers['Content-Length'] = Buffer.byteLength(bodyStr);
  return httpsRequest(
    { hostname: 'developers.hostinger.com', port: 443, path: '/api' + apiPath, method, headers },
    bodyStr
  );
}

async function cloudflare(method, apiPath, body) {
  const bodyStr = body ? JSON.stringify(body) : undefined;
  const headers = {
    Authorization: `Bearer ${cfg.cloudflareToken}`,
    'Content-Type': 'application/json'
  };
  if (bodyStr) headers['Content-Length'] = Buffer.byteLength(bodyStr);
  return httpsRequest(
    { hostname: 'api.cloudflare.com', port: 443, path: '/client/v4' + apiPath, method, headers },
    bodyStr
  );
}

let cfZoneId = null;
let cfZoneForId = null;

async function resolveCfZoneId() {
  if (cfZoneId && cfZoneForId === cfg.cloudflareZone) return cfZoneId;
  const r = await cloudflare('GET', `/zones?name=${encodeURIComponent(cfg.cloudflareZone)}`);
  if (r.status === 200 && r.body?.result?.[0]) {
    cfZoneId = r.body.result[0].id;
    cfZoneForId = cfg.cloudflareZone;
  }
  return cfZoneId;
}

async function fetchCloudflareData() {
  if (!cfg.cloudflareToken || !cfg.cloudflareZone) return null;
  const zoneId = await resolveCfZoneId();
  if (!zoneId) return null;

  const until = new Date();
  const since = new Date(until.getTime() - 24 * 60 * 60 * 1000);
  const analyticsQuery = {
    query: `query ($zoneTag: String!, $since: Time!, $until: Time!) {
      viewer { zones(filter: { zoneTag: $zoneTag }) {
        httpRequests1hGroups(limit: 24, filter: { datetime_geq: $since, datetime_leq: $until }) {
          sum { requests bytes cachedRequests threats }
        }
      } }
    }`,
    variables: { zoneTag: zoneId, since: since.toISOString(), until: until.toISOString() }
  };

  const [zoneRes, dnsRes, analyticsRes] = await Promise.all([
    cloudflare('GET', `/zones/${zoneId}`),
    cloudflare('GET', `/zones/${zoneId}/dns_records?per_page=100`),
    cloudflare('POST', '/graphql', analyticsQuery)
  ]);

  const zone   = zoneRes.status === 200 ? zoneRes.body?.result : null;
  const dns    = dnsRes.status === 200 ? (dnsRes.body?.result || []) : [];
  const groups = analyticsRes.status === 200
    ? (analyticsRes.body?.data?.viewer?.zones?.[0]?.httpRequests1hGroups || [])
    : [];

  const totals = groups.reduce((acc, g) => ({
    requests: acc.requests + g.sum.requests,
    bytes: acc.bytes + g.sum.bytes,
    cachedRequests: acc.cachedRequests + g.sum.cachedRequests,
    threats: acc.threats + g.sum.threats
  }), { requests: 0, bytes: 0, cachedRequests: 0, threats: 0 });

  return {
    zone: zone ? { name: zone.name, status: zone.status, plan: zone.plan?.name, nameServers: zone.name_servers || [] } : null,
    dns: dns.map(r => ({ type: r.type, name: r.name, content: r.content, proxied: r.proxied })),
    analytics: {
      requests: totals.requests,
      bytes: totals.bytes,
      cacheHitPct: totals.requests ? Math.round((totals.cachedRequests / totals.requests) * 1000) / 10 : 0,
      threats: totals.threats
    }
  };
}

async function fetchCloudflareFirewallEvents() {
  const zoneId = await resolveCfZoneId();
  if (!zoneId) return [];

  const until = new Date();
  const since = new Date(until.getTime() - 23.5 * 60 * 60 * 1000); // Cloudflare caps ranges at 1 day
  const query = {
    query: `query ($zoneTag: String!, $since: Time!, $until: Time!) {
      viewer { zones(filter: { zoneTag: $zoneTag }) {
        firewallEventsAdaptive(limit: 30, filter: { datetime_geq: $since, datetime_leq: $until }) {
          action clientRequestHTTPHost clientCountryName clientIP source datetime
        }
      } }
    }`,
    variables: { zoneTag: zoneId, since: since.toISOString(), until: until.toISOString() }
  };

  const r = await cloudflare('POST', '/graphql', query);
  const events = r.status === 200 ? (r.body?.data?.viewer?.zones?.[0]?.firewallEventsAdaptive || []) : [];
  return events.slice().sort((a, b) => new Date(b.datetime) - new Date(a.datetime));
}

async function fetchSshKeys() {
  const r = await hostinger('GET', '/vps/v1/public-keys');
  const data = r.status === 200 && Array.isArray(r.body?.data) ? r.body.data : [];
  return data.map(k => {
    const parts    = (k.key || '').trim().split(/\s+/);
    const type     = parts[0] || 'unknown';
    const keyBody  = parts[1] || '';
    const fingerprint = keyBody
      ? crypto.createHash('sha256').update(Buffer.from(keyBody, 'base64')).digest('base64')
      : null;
    return { id: k.id, name: k.name, type, fingerprint };
  });
}

const CERT_ORIGIN_HOST = '2.24.107.27'; // Hostinger VPS — NPM terminates TLS here for every app, even claudeapps-hosted ones

function checkCertExpiry(hostname) {
  return new Promise(resolve => {
    const socket = tls.connect({ host: CERT_ORIGIN_HOST, port: 443, servername: hostname, timeout: 5000, rejectUnauthorized: false }, () => {
      const cert = socket.getPeerCertificate();
      socket.end();
      if (!cert || !cert.valid_to) return resolve({ hostname, error: true });
      const validTo  = new Date(cert.valid_to);
      const daysLeft = Math.round((validTo - Date.now()) / (1000 * 60 * 60 * 24));
      resolve({ hostname, issuer: cert.issuer?.O || null, validTo: validTo.toISOString(), daysLeft });
    });
    socket.on('error', () => resolve({ hostname, error: true }));
    socket.on('timeout', () => { socket.destroy(); resolve({ hostname, error: true }); });
  });
}

async function fetchCertExpiries() {
  const hostnames = [...new Set(cfg.apps.map(a => { try { return new URL(a.url).hostname; } catch { return null; } }).filter(Boolean))];
  return Promise.all(hostnames.map(checkCertExpiry));
}

async function httpCheck(url) {
  const t0 = Date.now();
  return new Promise(resolve => {
    const u = new URL(url);
    const mod = u.protocol === 'https:' ? https : http;
    const req = mod.request({
      hostname: u.hostname,
      port: Number(u.port) || (u.protocol === 'https:' ? 443 : 80),
      path: u.pathname || '/',
      method: 'HEAD',
      timeout: 5000
    }, res => resolve({ up: res.statusCode < 500, ms: Date.now() - t0 }));
    req.on('error', () => resolve({ up: false, ms: Date.now() - t0 }));
    req.on('timeout', () => { req.destroy(); resolve({ up: false, ms: 5000 }); });
    req.end();
  });
}

async function fetchVmMetrics(id) {
  const to   = new Date();
  const from = new Date(to.getTime() - 2 * 24 * 60 * 60 * 1000);
  const fmt  = d => d.toISOString().slice(0, 10);
  const r = await hostinger('GET', `/vps/v1/virtual-machines/${id}/metrics?date_from=${fmt(from)}&date_to=${fmt(to)}`);
  if (r.status !== 200 || !r.body) return null;

  const latest = {};
  for (const key of ['cpu_usage', 'ram_usage', 'disk_space', 'incoming_traffic', 'outgoing_traffic', 'uptime']) {
    const metric = r.body[key];
    if (!metric || !metric.usage) continue;
    const timestamps = Object.keys(metric.usage).map(Number);
    if (!timestamps.length) continue;
    const maxTs = Math.max(...timestamps);
    latest[key] = { value: metric.usage[maxTs], unit: metric.unit, ts: maxTs };
  }
  return latest;
}

async function fetchVmBackups(id) {
  const r = await hostinger('GET', `/vps/v1/virtual-machines/${id}/backups`);
  const data = r.status === 200 && r.body && Array.isArray(r.body.data) ? r.body.data : [];
  if (!data.length) return { count: 0, latest: null };
  const latest = data.reduce((a, b) => (new Date(a.created_at) > new Date(b.created_at) ? a : b));
  return { count: data.length, latest: latest.created_at };
}

// ── Auth middleware ───────────────────────────────────────────────────────────
async function requireAuth(req) {
  const h = req.headers.authorization || '';
  return h.startsWith('Bearer ') ? verifyToken(h.slice(7)) : null;
}

// ── Route handlers ────────────────────────────────────────────────────────────
async function handleLogin(req, res) {
  const body    = await readBody(req);
  const u       = new URL(cfg.authUrl + '/login');
  const bodyStr = JSON.stringify(body);
  const r = await httpsRequest({
    hostname: u.hostname, port: Number(u.port) || 443,
    path: u.pathname, method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(bodyStr) }
  }, bodyStr);
  if (r.status === 200 && r.body && r.body.user) {
    logActivity('login', `${r.body.user.email} signed in`, r.body.user.email);
  }
  json(res, r.status, r.body);
}

async function handleMe(req, res) {
  const user = await requireAuth(req);
  if (!user) return json(res, 401, { error: 'Unauthorized' });
  json(res, 200, user);
}

async function handleDashboard(req, res) {
  const user = await requireAuth(req);
  if (!user) return json(res, 401, { error: 'Unauthorized' });
  const [vpsRes, cloudflareData, ...checks] = await Promise.all([
    hostinger('GET', '/vps/v1/virtual-machines'),
    fetchCloudflareData(),
    ...cfg.apps.map(a => httpCheck(a.url))
  ]);
  const list = Array.isArray(vpsRes.body) ? vpsRes.body : (vpsRes.body?.data || []);
  const apps = cfg.apps.map((a, i) => ({ ...a, ...checks[i] }));
  const activity = loadActivity().slice(-8).reverse();
  json(res, 200, {
    vps: {
      total:  list.length,
      online: list.filter(v => (v.status || v.state) === 'running').length,
      list
    },
    apps,
    appsOnline: apps.filter(a => a.up).length,
    activity,
    cloudflare: cloudflareData
  });
}

async function handleCloudflare(req, res) {
  const user = await requireAuth(req);
  if (!user) return json(res, 401, { error: 'Unauthorized' });
  json(res, 200, await fetchCloudflareData());
}

async function handleNetworking(req, res) {
  const user = await requireAuth(req);
  if (!user) return json(res, 401, { error: 'Unauthorized' });
  const [vpsRes, cf] = await Promise.all([
    hostinger('GET', '/vps/v1/virtual-machines'),
    fetchCloudflareData()
  ]);
  const list = Array.isArray(vpsRes.body) ? vpsRes.body : (vpsRes.body?.data || []);
  json(res, 200, {
    vps: list.map(v => ({ hostname: v.hostname, ipv4: v.ipv4 || [], ipv6: v.ipv6 || [], ns1: v.ns1, ns2: v.ns2 })),
    cloudflare: cf ? { zone: cf.zone, dns: cf.dns } : null
  });
}

async function handleSshKeys(req, res) {
  const user = await requireAuth(req);
  if (!user) return json(res, 401, { error: 'Unauthorized' });
  json(res, 200, await fetchSshKeys());
}

async function handleAlerts(req, res) {
  const user = await requireAuth(req);
  if (!user) return json(res, 401, { error: 'Unauthorized' });
  const [firewallEvents, certExpiries] = await Promise.all([
    fetchCloudflareFirewallEvents(),
    fetchCertExpiries()
  ]);
  json(res, 200, { firewallEvents, certExpiries });
}

async function handleVps(req, res) {
  const user = await requireAuth(req);
  if (!user) return json(res, 401, { error: 'Unauthorized' });
  const r = await hostinger('GET', '/vps/v1/virtual-machines');
  if (r.status !== 200) return json(res, r.status, r.body);

  const list = Array.isArray(r.body) ? r.body : (r.body?.data || []);
  const enriched = await Promise.all(list.map(async vm => {
    const [metrics, backups] = await Promise.all([fetchVmMetrics(vm.id), fetchVmBackups(vm.id)]);
    return { ...vm, metrics, backups };
  }));
  json(res, 200, enriched);
}

async function handleVpsRestart(req, res, id) {
  const user = await requireAuth(req);
  if (!user) return json(res, 401, { error: 'Unauthorized' });
  const r  = await hostinger('POST', `/vps/v1/virtual-machines/${encodeURIComponent(id)}/restart`);
  const ok = r.status >= 200 && r.status < 300;
  logActivity('vps_restart', `${user.email} ${ok ? 'restarted' : 'attempted to restart'} VPS ${id}`, user.email);
  json(res, r.status, r.body);
}

async function handleBilling(req, res) {
  const user = await requireAuth(req);
  if (!user) return json(res, 401, { error: 'Unauthorized' });
  const r = await hostinger('GET', '/billing/v1/orders');
  json(res, r.status, r.body);
}

async function handleApps(req, res) {
  const user = await requireAuth(req);
  if (!user) return json(res, 401, { error: 'Unauthorized' });
  const checks = await Promise.all(cfg.apps.map(a => httpCheck(a.url)));
  json(res, 200, cfg.apps.map((a, i) => ({ ...a, ...checks[i] })));
}

function serveHtml(res) {
  try {
    const data = fs.readFileSync(path.join(__dirname, 'index.html'));
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Content-Length': data.length });
    res.end(data);
  } catch { json(res, 500, { error: 'Could not read index.html' }); }
}

// ── Server ────────────────────────────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'");
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');

  const { method } = req;
  const pathname   = req.url.split('?')[0];

  try {
    if ((pathname === '/' || pathname === '/index.html') && method === 'GET') return serveHtml(res);
    if (pathname === '/api/login'     && method === 'POST') return handleLogin(req, res);
    if (pathname === '/api/me'        && method === 'GET')  return handleMe(req, res);
    if (pathname === '/api/dashboard' && method === 'GET')  return handleDashboard(req, res);
    if (pathname === '/api/vps'       && method === 'GET')  return handleVps(req, res);
    if (pathname === '/api/billing'   && method === 'GET')  return handleBilling(req, res);
    if (pathname === '/api/apps'      && method === 'GET')  return handleApps(req, res);
    if (pathname === '/api/cloudflare' && method === 'GET') return handleCloudflare(req, res);
    if (pathname === '/api/networking' && method === 'GET') return handleNetworking(req, res);
    if (pathname === '/api/ssh-keys'   && method === 'GET') return handleSshKeys(req, res);
    if (pathname === '/api/alerts'     && method === 'GET') return handleAlerts(req, res);

    const restartMatch = pathname.match(/^\/api\/vps\/([^/]+)\/restart$/);
    if (restartMatch && method === 'POST') return handleVpsRestart(req, res, restartMatch[1]);

    json(res, 404, { error: 'Not found' });
  } catch (err) {
    console.error('Unhandled error:', err);
    json(res, 500, { error: 'Internal server error' });
  }
});

server.listen(cfg.port, () => console.log(`newtekk-manage listening on port ${cfg.port}`));
