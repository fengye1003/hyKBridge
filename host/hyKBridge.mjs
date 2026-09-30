#!/usr/bin/env node
/*
 * hyKBridge.mjs — hyKBridge host application (the PC side).
 *
 * PURPOSE: give an agent framework (DSH or anything similar) and a human remote
 * access to a Kindle's shell and to its operations -- shell commands, files, the
 * book library, KUAL extensions -- without a cloud, an account or a third party.
 *
 * Two channels:
 *   PULL   the device is the active party: it wakes, finds this host on the LAN and
 *          pulls a command. Works while the device is asleep; higher latency.
 *   DIRECT the host talks straight to the device management service (:8090, token).
 *          Full capabilities, low latency -- but the device must be AWAKE.
 * Waking the device is a DERIVED problem: we solve it so that the direct channel is
 * reachable at any time, not for its own sake.
 *
 * Zero npm dependencies. One file. Runs anywhere Node 18+ runs.
 *
 *   node hyKBridge.mjs serve                 run the host (HTTP + UDP beacon)
 *   node hyKBridge.mjs pair --kindle <ip> --code 123456 [--name my-pc]
 *   node hyKBridge.mjs exec "<command>"      PULL: enqueue a command for the device
 *   node hyKBridge.mjs push <file> [--as n]  PULL: enqueue a file for the device
 *   node hyKBridge.mjs list | result <job>   PULL: queue + results
 *   node hyKBridge.mjs device <cmd> [args]   DIRECT: status/exec/ls/cat/get/put/books/ext…
 *   node hyKBridge.mjs device-token <token>  store the direct-channel token
 *   node hyKBridge.mjs status [--json]       paired devices / ports / counts
 *
 * Every subcommand takes --json (stdout is JSON only) with stable exit codes
 * (0 ok / 1 error / 2 usage / 3 no token / 4 unreachable / 124 device timeout) --
 * that contract is what makes it callable from an agent framework. See docs/AGENT.md.
 *
 * Mutual auth (both sides hold the same secret, created at pairing):
 *   device -> host : X-Dev, X-Ts, X-Sig = HMAC(secret, dev|ts|method|path)
 *   host -> device : X-Host-Sig        = HMAC(secret, body)
 * The device MUST verify X-Host-Sig before running anything: commands run as root
 * on the device, so a rogue host on the LAN is the real threat.
 */
import crypto from "node:crypto";
import dgram from "node:dgram";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const HOME = process.env.HYKBRIDGE_HOME || path.join(HERE, ".hyKBridge");
const CFG_F = path.join(HOME, "host.json");
const QUEUE = path.join(HOME, "queue");
const RESULTS = path.join(HOME, "results");
const BEACON_PORT = Number(process.env.HYKBRIDGE_BEACON || 8093);
const DEFAULT_PORTS = [8091, 8092];
const APP = "hyKBridge";
const VERSION = "0.1.0";
const COPYRIGHT = [
  "== HyKBridge by HYrecovery & HoshinoSumi from teko.IO SisTemS! ==",
  "== Under MIT Open Source License =="
].join("\n");
const banner = (stream = process.stdout) => {
  if (process.env.HYKBRIDGE_QUIET) return;      // HYKBRIDGE_QUIET=1 keeps output machine-readable
  stream.write(COPYRIGHT + "\n");
};

fs.mkdirSync(QUEUE, { recursive: true });
fs.mkdirSync(RESULTS, { recursive: true });

// ── config ────────────────────────────────────────────────────────
function loadCfg() {
  if (fs.existsSync(CFG_F)) return JSON.parse(fs.readFileSync(CFG_F, "utf8"));
  const cfg = {
    host_id: crypto.randomBytes(8).toString("hex"),
    name: os.hostname(),
    ports: DEFAULT_PORTS,
    paired: {}            // device_id -> { name, secret, paired_at, last_seen }
  };
  saveCfg(cfg);
  return cfg;
}
function saveCfg(cfg) { fs.mkdirSync(HOME, { recursive: true }); fs.writeFileSync(CFG_F, JSON.stringify(cfg, null, 2) + "\n"); }

const hmac = (secret, data) => crypto.createHmac("sha256", secret).update(data).digest("hex");
const safeEq = (a, b) => {
  const A = Buffer.from(String(a)), B = Buffer.from(String(b));
  return A.length === B.length && crypto.timingSafeEqual(A, B);
};

// ── job queue ─────────────────────────────────────────────────────
function enqueue(job) {
  const id = new Date().toISOString().replace(/[-:.TZ]/g, "").slice(0, 14) + "-" + crypto.randomBytes(3).toString("hex");
  fs.writeFileSync(path.join(QUEUE, id + ".json"), JSON.stringify({ id, ...job, created: Date.now() }));
  return id;
}
function takeNext() {
  const files = fs.readdirSync(QUEUE).filter((f) => f.endsWith(".json")).sort();
  if (!files.length) return null;
  const f = files[0];
  const job = JSON.parse(fs.readFileSync(path.join(QUEUE, f), "utf8"));
  fs.renameSync(path.join(QUEUE, f), path.join(QUEUE, f + ".taken"));
  return job;
}
// a taken job that never came back within 10 minutes goes back to the queue
function requeueStale() {
  const now = Date.now();
  for (const f of fs.readdirSync(QUEUE).filter((x) => x.endsWith(".taken"))) {
    const p = path.join(QUEUE, f);
    try {
      const job = JSON.parse(fs.readFileSync(p, "utf8").replace(/\n$/, ""));
      if (now - job.created > 600000) { fs.renameSync(p, p.replace(/\.taken$/, "")); }
    } catch { /* ignore */ }
  }
}

// ── auth ──────────────────────────────────────────────────────────
let lastSeenSavedAt = 0;   // throttles the config rewrite done by authDevice()
function authDevice(cfg, req, url) {
  const dev = req.headers["x-dev"] || url.searchParams.get("dev") || "";
  const ts = req.headers["x-ts"] || url.searchParams.get("ts") || "";
  const sig = req.headers["x-sig"] || url.searchParams.get("sig") || "";
  const rec = cfg.paired[dev];
  if (!rec) return { ok: false, why: "device not paired" };
  if (!/^\d+$/.test(ts) || Math.abs(Date.now() / 1000 - Number(ts)) > 300) return { ok: false, why: "stale timestamp" };
  const want = hmac(rec.secret, [dev, ts, req.method, url.pathname].join("|"));
  if (!safeEq(want, sig)) return { ok: false, why: "bad signature" };
  const nowMs = Date.now();
  rec.last_seen = nowMs;
  // Persist at most once a minute. host.json holds every shared secret, and the
  // device polls on every wake-up -- rewriting it each time would be pointless churn.
  if (nowMs - lastSeenSavedAt > 60000) { lastSeenSavedAt = nowMs; saveCfg(cfg); }
  return { ok: true, dev, rec };
}

// ── HTTP ──────────────────────────────────────────────────────────
function send(res, code, body, extra = {}) {
  const b = Buffer.isBuffer(body) ? body : Buffer.from(String(body));
  res.writeHead(code, { "Content-Length": b.length, "Cache-Control": "no-store", ...extra });
  res.end(b);
}

function makeServer(cfg, port) {
  const srv = http.createServer((req, res) => {
    const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);

    // discovery marker: unauthenticated, static, tells the device "a host is here"
    if (url.pathname === "/__hello") {
      return send(res, 200, JSON.stringify({
        app: APP, version: VERSION, host_id: cfg.host_id, name: cfg.name, port,
        paired: Object.keys(cfg.paired).length
      }), { "Content-Type": "application/json" });
    }

    const a = authDevice(cfg, req, url);
    if (!a.ok) {
      return send(res, 401, JSON.stringify({ ok: false, error: a.why }), { "Content-Type": "application/json" });
    }

    // long-poll: hold the request until a job shows up or `hold` seconds pass
    if (url.pathname === "/next" && req.method === "GET") {
      const hold = Math.min(Number(url.searchParams.get("hold") || 25), 120);
      requeueStale();
      const reply = (job) => {
        if (!job) return send(res, 204, "");
        const body = job.type === "exec" ? job.cmd : JSON.stringify({ type: "file", name: job.name, bytes: job.bytes, url: `/file/${job.id}` });
        send(res, 200, body, {
          "Content-Type": "text/plain; charset=utf-8",
          "X-Job-Id": job.id, "X-Job-Type": job.type,
          "X-Host-Sig": hmac(a.rec.secret, body)          // device verifies this before acting
        });
      };
      const first = takeNext();
      if (first) return reply(first);
      const t0 = Date.now();
      const timer = setInterval(() => {
        const job = takeNext();
        if (job) { clearInterval(timer); reply(job); }
        else if (Date.now() - t0 > hold * 1000) { clearInterval(timer); reply(null); }
      }, 500);
      res.on("close", () => clearInterval(timer));
      return;
    }

    // file transfer for a queued "push" job
    if (url.pathname.startsWith("/file/") && req.method === "GET") {
      const id = url.pathname.slice(6);
      const p = path.join(QUEUE, id + ".json.taken");
      const pq = path.join(QUEUE, id + ".json");
      const src = fs.existsSync(p) ? p : (fs.existsSync(pq) ? pq : null);
      if (!src) return send(res, 404, "no such file job");
      const job = JSON.parse(fs.readFileSync(src, "utf8"));
      if (!fs.existsSync(job.file)) return send(res, 410, "file gone");
      const data = fs.readFileSync(job.file);
      return send(res, 200, data, {
        "Content-Type": "application/octet-stream", "Content-Length": data.length,
        "X-Host-Sig": hmac(a.rec.secret, crypto.createHash("sha256").update(data).digest("hex"))
      });
    }

    if (url.pathname === "/result" && req.method === "POST") {
      const id = url.searchParams.get("job") || "unknown";
      const chunks = [];
      req.on("data", (d) => { if (chunks.reduce((x, y) => x + y.length, 0) < 4 * 1048576) chunks.push(d); });
      req.on("end", () => {
        const body = Buffer.concat(chunks).toString("utf8");
        fs.writeFileSync(path.join(RESULTS, id + ".txt"), body);
        for (const f of [path.join(QUEUE, id + ".json.taken"), path.join(QUEUE, id + ".json")]) {
          try { fs.unlinkSync(f); } catch {}
        }
        console.log(`[${new Date().toISOString().slice(11, 19)}] result from ${a.dev.slice(0, 8)}… job ${id} (${body.length}B)`);
        send(res, 200, JSON.stringify({ ok: true }), { "Content-Type": "application/json" });
      });
      return;
    }

    return send(res, 404, JSON.stringify({ ok: false, error: "no such endpoint" }), { "Content-Type": "application/json" });
  });
  srv.on("error", () => {});
  return srv;
}

// ── UDP beacon: lets the device find this host in one packet ──────
function startBeacon(cfg, port) {
  const sock = dgram.createSocket({ type: "udp4", reuseAddr: true });
  sock.on("error", () => {});
  sock.bind(() => {
    try { sock.setBroadcast(true); } catch {}
    const payload = Buffer.from("HYKBRIDGE1 " + JSON.stringify({ ip: "", port, host_id: cfg.host_id, name: cfg.name, app: APP }));
    const tick = () => {
      try { sock.send(payload, 0, payload.length, BEACON_PORT, "255.255.255.255"); } catch {}
    };
    tick();
    setInterval(tick, 2000);
    console.log(`[i]  UDP beacon on :${BEACON_PORT} every 2s (broadcast 255.255.255.255)`);
  });
}

// ── pairing: the PC asks the KINDLE to accept it ──────────────────
async function pair(args) {
  const cfg = loadCfg();
  const kindle = args.kindle, code = args.code;
  if (!kindle || !code) die("usage: hyKBridge.mjs pair --kindle <ip> --code <6 digits> [--name my-pc]");
  if (!/^\d{6}$/.test(code)) die("code must be 6 digits");
  const secret = crypto.randomBytes(32).toString("hex");
  const ports = cfg.ports;
  let lastErr = "";
  for (const p of ports) {
    try {
      const r = await fetch(`http://${kindle}:${p}/api/pair`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code, secret, name: args.name || os.hostname(), ports })
      });
      const j = await r.json().catch(() => ({}));
      if (r.status !== 200 || !j.ok) { lastErr = `${p}: ${JSON.stringify(j).slice(0, 200)}`; continue; }
      cfg.paired[j.device_id] = { name: args.name || os.hostname(), secret, paired_at: Date.now(), kindle, ports };
      saveCfg(cfg);
      console.log(`[OK] 配对成功：设备 ${j.device_id.slice(0, 12)}…（${j.device_name || "kindle"}）`);
      console.log(`     密钥只在你我两端各存一份（本机 host.json / 设备 state/pair.json），未打印。`);
      return 0;
    } catch (e) { lastErr = `${p}: ${e.message}`; }
  }
  die(`配对失败（设备需在同一个局域网，且 KUAL 里已点出 6 位码）：${lastErr}`);
}

// ── DIRECT CHANNEL ────────────────────────────────────────────────
// hyKBridge has two channels, and they exist for different reasons:
//
//   1. DIRECT (this section)  -- talk straight to the device management service
//      on :8090 with a token. Full shell + file + extension operations, low
//      latency. This is the "get a shell on the Kindle" part. It needs the
//      device to be AWAKE.
//   2. PULL (exec/push/result) -- the host queue. The device comes and fetches
//      work on its own schedule. This is what makes the direct channel reachable
//      ANY time; waking the device is a derived problem we solve to keep this
//      channel available, not the point of the project.
//
// For an agent framework (DSH, or anything else) the usual flow is:
//   pull channel  -> queue a command, come back for the result (device may be asleep)
//   direct channel -> once the device is up, do interactive/latency-sensitive work
const DEVICE_TOKEN_F = path.join(HOME, "device-token.txt");
const fp12 = (s) => crypto.createHash("sha256").update(String(s)).digest("hex").slice(0, 12);

const DIRECT = {
  ping:      { m: "GET",  p: () => "/__ping", open: true, help: "is the device awake and serving?" },
  status:    { m: "GET",  p: () => "/api/status", help: "python/disk/ports/token fingerprint" },
  exec:      { m: "POST", p: () => "/api/exec", body: (q) => ({ cmd: q.join(" ") }), help: "<cmd>  run a shell command (cwd /mnt/us)" },
  keepawake: { m: "GET",  p: () => "/api/keepawake", help: "preventScreenSaver state" },
  sleep:     { m: "POST", p: () => "/api/sleep", body: (q) => ({ secs: Number(q[0] || 100) }), write: true, help: "[secs] suspend the device (it will wake itself)" },
  ls:        { m: "GET",  p: (q) => "/api/ls?path=" + encodeURIComponent(q[0] || "/documents"), help: "[path] list a directory" },
  cat:       { m: "GET",  p: (q) => `/api/read?path=${encodeURIComponent(q[0])}&max=${Number(q[1] || 20000)}`, help: "<path> [max] read a text file" },
  books:     { m: "GET",  p: () => "/api/books", help: "library summary + damaged thumbnails" },
  ext:       { m: "GET",  p: () => "/api/ext", help: "KUAL extensions (on/off)" },
  backups:   { m: "GET",  p: () => "/api/backups", help: "extension backups on the device" },
  "ext-on":  { m: "POST", p: () => "/api/ext/toggle", body: (q) => ({ name: q[0], enabled: true }), write: true, help: "<name>" },
  "ext-off": { m: "POST", p: () => "/api/ext/toggle", body: (q) => ({ name: q[0], enabled: false }), write: true, help: "<name>" },
  backup:    { m: "POST", p: () => "/api/ext/backup", body: (q) => ({ name: q[0] }), write: true, help: "<name> zip an extension" },
  mkdir:     { m: "POST", p: () => "/api/mkdir", body: (q) => ({ path: q[0] }), write: true, help: "<path>" },
  rm:        { m: "POST", p: () => "/api/rm", body: (q) => ({ path: q[0] }), write: true, help: "<path>" },
  mv:        { m: "POST", p: () => "/api/mv", body: (q) => ({ src: q[0], dst: q[1] }), write: true, help: "<src> <dst>" },
  get:       { m: "GET",  p: (q) => "/api/get?path=" + encodeURIComponent(q[0]), raw: true, help: "<path> [--out F] download a file" },
  put:       { m: "POST", p: (q) => "/api/put?path=" + encodeURIComponent(q[1]), file: (q) => q[0], write: true, help: "<local> <remote>" }
};

function devTarget(cfg, a) {
  // Default to the device we paired with: pairing already taught us its IP, so the
  // address is never configured by hand on this path either.
  const rec = Object.entries(cfg.paired).map(([id, r]) => ({ id, ...r })).sort((x, y) => (y.last_seen || 0) - (x.last_seen || 0))[0] || {};
  return { host: String(a.kindle || a.host || rec.kindle || ""), port: Number(a.port || 8090), dev: rec.id || "" };
}

function devToken(a) {
  if (a.token) return String(a.token);
  if (process.env.HYKBRIDGE_TOKEN) return process.env.HYKBRIDGE_TOKEN;
  try { return fs.readFileSync(DEVICE_TOKEN_F, "utf8").trim(); } catch { return ""; }
}

function devReq(t, token, method, p, body, extra = {}) {
  return new Promise((resolve, reject) => {
    const headers = { ...(token ? { "X-Auth": token } : {}), ...extra };
    // Content-Length is mandatory: without it Node sends chunked and the device
    // (which reads by Content-Length) sees an empty body.
    if (body) headers["Content-Length"] = Buffer.byteLength(body);
    const r = http.request({ host: t.host, port: t.port, method, path: p, headers, timeout: 30000 }, (res) => {
      const chunks = [];
      res.on("data", (d) => chunks.push(d));
      res.on("end", () => resolve({ status: res.statusCode, body: Buffer.concat(chunks) }));
    });
    r.on("error", reject);
    r.on("timeout", () => r.destroy(new Error("timeout")));
    if (body) r.write(body);
    r.end();
  });
}

async function deviceCmd(cfg, a) {
  const sub = a._[0];
  const j = !!a.json;                       // machine-readable mode: stdout is JSON only
  // Exit-code contract for agent callers: 0 ok · 1 error · 2 usage · 3 no token
  // · 4 device unreachable · 124 device-side timeout.
  const dieCode = (code, m) => { console.error("[NG] " + m); process.exit(code); };
  if (!sub || sub === "help") {
    console.log(`hyKBridge direct channel — talk to the device management service (device must be AWAKE)

  node hyKBridge.mjs device <cmd> [args] [--kindle <ip>] [--port 8090]
                                          [--token T] [--write] [--json]

  ${Object.entries(DIRECT).map(([k, v]) => `${k.padEnd(10)} ${v.write ? "[write] " : "        "}${v.help}`).join("\n  ")}

  token: --token / HYKBRIDGE_TOKEN / ${DEVICE_TOKEN_F}
         (the device holds it in state/token.txt; KUAL → Show Status shows the fingerprint)
  exit : 0 ok · 1 error · 2 usage · 3 no token · 4 unreachable · 124 device-side timeout
         (--json makes stdout a single JSON object, so a caller never has to parse text)
  sleep: if the device is asleep this channel just fails — queue the work through the
         pull channel instead:  hyKBridge.mjs exec "<cmd>"  then  hyKBridge.mjs result <job>`);
    return 0;
  }
  const spec = DIRECT[sub];
  if (!spec) return dieCode(2, `unknown device command: ${sub} (try: hyKBridge.mjs device help)`);
  const q = a._.slice(1);
  const t = devTarget(cfg, a);
  if (!t.host) return dieCode(2, "no device address: pass --kindle <ip>, or run pair once (the address is remembered)");
  if (spec.write && !a.write) return dieCode(2, "write op: pass --write to confirm (read-only by default)");
  const token = devToken(a);
  if (!spec.open && !token) return dieCode(3, `no device token — run:  node hyKBridge.mjs device-token <token>\n     (the device prints it from KUAL → Show Status; state/token.txt on the device)`);

  let body = null, extra = {};
  if (spec.file) { body = fs.readFileSync(spec.file(q)); extra["Content-Type"] = "application/octet-stream"; }
  else if (spec.body) { body = JSON.stringify(spec.body(q)); extra["Content-Type"] = "application/json"; }
  const p = spec.p(q);

  let r;
  try { r = await devReq(t, spec.open ? "" : token, spec.m, p, body, extra); }
  catch (e) {
    const asleep = `device unreachable at ${t.host}:${t.port} (${e.message})`;
    if (j) console.log(JSON.stringify({ ok: false, error: "unreachable", detail: asleep, host: t.host, port: t.port }));
    else console.error(`[NG] ${asleep}\n     It may be asleep. That is what the pull channel is for:\n       hyKBridge.mjs exec "<cmd>"   ->   hyKBridge.mjs result <job>`);
    return 4;
  }

  if (spec.raw) {
    if (r.status !== 200) {
      if (j) console.log(JSON.stringify({ ok: false, status: r.status, error: r.body.toString("utf8").slice(0, 300) }));
      else console.error(`[NG] HTTP ${r.status} ${r.body.toString("utf8").slice(0, 200)}`);
      return 1;
    }
    const out = a.out || path.basename(q[0] || "download.bin");
    fs.writeFileSync(out, r.body);
    if (j) console.log(JSON.stringify({ ok: true, saved: out, bytes: r.body.length, remote: q[0] }));
    else console.log(`[OK] ${r.body.length} bytes -> ${out}`);
    return 0;
  }

  let data = null;
  try { data = JSON.parse(r.body.toString("utf8")); } catch { data = { raw: r.body.toString("utf8").slice(0, 4000) }; }
  const ok = r.status === 200 && data.ok !== false;

  if (j) {
    console.log(JSON.stringify({ ok, status: r.status, device: t.host, command: sub, data }));
    if (data && data.rc === 124) return 124;               // device-side timeout
    return ok ? 0 : 1;
  }

  // ── human rendering ──
  if (!ok) { console.error(`[NG] HTTP ${r.status} ${JSON.stringify(data).slice(0, 400)}`); return 1; }
  if (sub === "exec") {
    process.stdout.write(data.stdout || "");
    if (data.stderr) process.stderr.write(data.stderr);
    console.log(`[rc=${data.rc}${data.blocked ? " BLOCKED" : ""}]`);
    return data.rc === 124 ? 124 : 0;
  }
  if (sub === "ls") {
    for (const it of data.items || []) console.log(`${it.dir ? "D" : "F"} ${String(it.bytes).padStart(10)}  ${it.mtime}  ${it.name}`);
    console.log(`[i] ${data.count} entries in ${data.path}`);
    return 0;
  }
  if (sub === "ext") {
    for (const e of data.items || []) console.log(`${e.enabled ? "[on] " : "[off]"} ${String(e.name).padEnd(16)} ${e.mtime}  ${e.bytes} B  ${e.menu_items === null ? "?" : e.menu_items + " items"}  ${e.title || ""} ${e.version || ""}`);
    return 0;
  }
  if (sub === "books") {
    console.log(`files=${data.files} bytes=${data.bytes} sdr=${data.sdr} thumbs=${data.thumbs} damaged=${data.thumbs_damaged}`);
    console.log(JSON.stringify(data.by_ext));
    return 0;
  }
  if (sub === "cat") { process.stdout.write(data.text || ""); if (data.truncated) console.log(`\n[i] truncated (${data.bytes} bytes total)`); return 0; }
  if (sub === "status") {
    for (const k of ["app", "version", "python", "pid", "uptime_s", "port", "root", "cwd", "token_fp", "read_only"]) console.log(`${k.padEnd(10)}: ${data[k]}`);
    if (data.ips) console.log(`ips       : ${data.ips.join(", ")}`);
    if (data.disk) console.log(`disk      : ${data.disk.free} free of ${data.disk.total} (${data.disk.used_pct}% used)`);
    return 0;
  }
  console.log(JSON.stringify(data, null, 1));
  return 0;
}

const die = (m) => { console.error("[NG] " + m); process.exit(1); };
// Host and device sit in the same room, so "last seen" is printed in LOCAL time --
// a UTC clock next to a device-local timestamp only invites confusion.
const hhmmss = (ms) => {
  const d = new Date(ms), p = (n) => String(n).padStart(2, "0");
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
};
function parseArgs(argv) {
  const o = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i].startsWith("--")) { o[argv[i].slice(2)] = (argv[i + 1] && !argv[i + 1].startsWith("--")) ? argv[++i] : true; }
    else o._.push(argv[i]);
  }
  return o;
}

// ── CLI ───────────────────────────────────────────────────────────
const argv = process.argv.slice(2);
const cmd = argv[0];
const a = parseArgs(argv.slice(1));
const cfg = loadCfg();
let serving = false;      // `serve` runs forever; every other branch exits on its own

if (!cmd || cmd === "help") {
  banner();
  console.log(`${APP} v${VERSION} — 远程拿到 Kindle 的 shell 与操作能力（给 Agent 框架和人用；局域网、无云、无第三方）

两个通道 / TWO CHANNELS
  PULL   设备睡着时也能用：把活儿排进队列，设备醒来自己来取，结果回传。
         exec "<命令>"            排一条命令
         push <文件> [--as 名字]   排一个文件（落到设备 /documents）
         list | result <job-id>   看队列 / 取结果
  DIRECT 设备醒着时用：直连设备管理服务，能力全、延迟低。
         device <子命令> [--write] [--json]     （device help 看全部子命令）
         device exec "<命令>" | status | ls | cat | get | put | books | ext | ext-on …

  serve                     起 host（HTTP + UDP 广播），PULL 通道的前提
  pair --kindle <ip> --code <6位码> [--name 名字]     配对一次（设备地址会被记住）
  device-token <token>      保存直连通道的口令（只打印指纹，绝不打印口令）
  status [--json]           看配对/端口/队列

  给 Agent：所有子命令支持 --json（stdout 只出 JSON），退出码 0 成功 / 1 失败 / 2 用法 / 3 无口令 / 4 设备不可达 / 124 设备端超时。
  详见 docs/AGENT.md。

  状态目录：${HOME}
`);
  process.exit(0);
}

if (cmd === "pair") process.exit(await pair(a));

// Save the device-management token without ever printing it (only its fingerprint).
if (cmd === "device-token") {
  const tok = a._[0] || process.env.HYKBRIDGE_TOKEN || "";
  if (!tok) die("usage: hyKBridge.mjs device-token <token>   (device: state/token.txt, or KUAL → Show Status)");
  fs.mkdirSync(HOME, { recursive: true });
  fs.writeFileSync(DEVICE_TOKEN_F, tok + "\n", { mode: 0o600 });
  console.log(`[OK] token stored in ${DEVICE_TOKEN_F}  (fingerprint ${fp12(tok)} — the token itself is never printed)`);
  process.exit(0);
}

// Direct channel: the device must be awake.
if (cmd === "device") {
  banner(process.stderr);
  process.exit(await deviceCmd(cfg, a));
}

if (cmd === "serve") {
  serving = true;
  banner();        // MUST be set, otherwise we fall through to the die() at the end
  const ports = (a.port ? [Number(a.port)] : cfg.ports);
  let started = 0;
  for (const p of ports) {
    const srv = makeServer(cfg, p);
    srv.listen(p, "0.0.0.0", () => {
      started++;
      console.log(`[OK] ${APP} host listening on 0.0.0.0:${p}  (host_id ${cfg.host_id}, paired ${Object.keys(cfg.paired).length})`);
      if (started === 1) startBeacon(cfg, p);
    });
  }
  console.log("[i]  等待设备来连：GET /__hello → GET /next?dev=…&hold=25 → POST /result");
  // do NOT process.exit() here: listen() is async and exiting now would kill the socket
  // before it binds. The started===0 check MUST sit inside the timeout -- done
  // synchronously it is always 0 and would kill a healthy server 2s after start-up.
  setTimeout(() => {
    if (!started) { console.error("[NG] no port could be bound (all candidates busy?)"); process.exit(1); }
  }, 2000);
}

if (cmd === "exec") {
  banner(process.stderr);       // stdout carries only the job id, so it stays pipeable
  const c = a._.join(" ");
  if (!c) die('usage: hyKBridge.mjs exec "<command>"');
  const id = enqueue({ type: "exec", cmd: c });
  console.log(id);
  process.exit(0);
}

if (cmd === "push") {
  banner(process.stderr);
  const f = a._[0];
  if (!f) die("usage: hyKBridge.mjs push <file> [--as name]");
  if (!fs.existsSync(f)) die("no such file: " + f);
  const abs = path.resolve(f);
  const id = enqueue({ type: "file", name: a.as || path.basename(abs), file: abs, bytes: fs.statSync(abs).size });
  console.log(id);
  process.exit(0);
}

if (cmd === "list") {
  banner(!!a.json ? process.stderr : process.stdout);
  const scan = (dir, suf) => fs.readdirSync(dir).filter((f) => f.endsWith(suf))
    .map((f) => ({ id: f.replace(suf, ""), bytes: fs.statSync(path.join(dir, f)).size }));
  const queue = scan(QUEUE, ".json"), taken = scan(QUEUE, ".taken"), results = scan(RESULTS, ".txt");
  if (a.json) { console.log(JSON.stringify({ ok: true, queue, taken, results })); process.exit(0); }
  for (const [label, items] of [["queue", queue], ["taken", taken], ["results", results]]) {
    console.log(`${label} (${items.length})`);
    for (const it of items) console.log(`  ${it.id}  ${it.bytes}B`);
  }
  process.exit(0);
}

if (cmd === "result") {
  banner(process.stderr);       // the stored output is the payload; keep stdout clean
  const id = (a._[0] || "").replace(/\.txt$/, "");
  const p = path.join(RESULTS, id + ".txt");
  if (!fs.existsSync(p)) die("no result " + id);
  process.stdout.write(fs.readFileSync(p, "utf8"));
  process.exit(0);
}

if (cmd === "status") {
  banner(!!a.json ? process.stderr : process.stdout);
  const paired = Object.entries(cfg.paired).map(([id, r]) => ({
    device_id: id, name: r.name, kindle: r.kindle || null,
    last_seen: r.last_seen ? new Date(r.last_seen).toISOString() : null, ports: r.ports || cfg.ports
  }));
  const queue = fs.readdirSync(QUEUE).filter((f) => f.endsWith(".json")).length;
  if (a.json) {
    console.log(JSON.stringify({ ok: true, host_id: cfg.host_id, name: cfg.name, ports: cfg.ports, paired, queue, results: fs.readdirSync(RESULTS).length, device_token: fs.existsSync(DEVICE_TOKEN_F) ? fp12(devToken({})) : null }));
    process.exit(0);
  }
  console.log("host_id :", cfg.host_id);
  console.log("name    :", cfg.name);
  console.log("ports   :", cfg.ports.join(", "));
  console.log("paired  :", paired.map((r) => `${r.device_id.slice(0, 12)}… (${r.name}, kindle ${r.kindle}, last seen ${r.last_seen ? hhmmss(Date.parse(r.last_seen)) : "never"})`).join("\n          ") || "（无）");
  console.log("queue   :", queue);
  console.log("results :", fs.readdirSync(RESULTS).length);
  console.log("dtoken  :", fs.existsSync(DEVICE_TOKEN_F) ? fp12(devToken({})) + "（直接通道可用）" : "未保存（device-token <token>）");
  process.exit(0);
}

if (!serving) { banner(process.stderr); die(`unknown command: ${cmd}（try help）`); }
