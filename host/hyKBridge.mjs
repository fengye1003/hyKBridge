#!/usr/bin/env node
/*
 * hyKBridge.mjs — hyKBridge host application (the PC side).
 *
 * The Kindle is the ACTIVE party: it wakes up, finds this host on the LAN, and
 * pulls a command. This side just waits, authenticates, and answers.
 *
 * Zero npm dependencies. One file. Runs anywhere Node 18+ runs.
 *
 *   node hyKBridge.mjs serve                 run the host (HTTP + UDP beacon)
 *   node hyKBridge.mjs pair --kindle <ip> --code 123456 [--name my-pc]
 *   node hyKBridge.mjs exec "<command>"      enqueue a command for the device
 *   node hyKBridge.mjs push <file> [--as n]  enqueue a file for the device
 *   node hyKBridge.mjs list                  queue + results
 *   node hyKBridge.mjs result <job>          print a stored result
 *   node hyKBridge.mjs status                paired devices / ports / counts
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
  console.log(`${APP} v${VERSION} — 让 Kindle 主动来找这台电脑（局域网，无云、无第三方）

  serve                     起 host（HTTP + UDP 广播）
  pair --kindle <ip> --code <6位码> [--name 名字]
  exec "<命令>"              给设备排一条命令
  push <文件> [--as 名字]     给设备排一个文件（落到设备的 /documents）
  list                      看队列与结果
  result <job-id>           打印某条结果
  status                    看配对/端口/队列

  状态目录：${HOME}
`);
  process.exit(0);
}

if (cmd === "pair") process.exit(await pair(a));

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
  banner();
  const show = (label, dir, suf) => {
    const items = fs.readdirSync(dir).filter((f) => f.endsWith(suf));
    console.log(`${label} (${items.length})`);
    for (const f of items) console.log("  " + f.replace(suf, "") + `  ${fs.statSync(path.join(dir, f)).size}B`);
  };
  show("queue", QUEUE, ".json"); show("taken", QUEUE, ".taken"); show("results", RESULTS, ".txt");
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
  banner();
  console.log("host_id :", cfg.host_id);
  console.log("name    :", cfg.name);
  console.log("ports   :", cfg.ports.join(", "));
  console.log("paired  :", Object.entries(cfg.paired).map(([id, r]) => `${id.slice(0, 12)}… (${r.name}, kindle ${r.kindle}, last seen ${r.last_seen ? hhmmss(r.last_seen) : "never"})`).join("\n          ") || "（无）");
  console.log("queue   :", fs.readdirSync(QUEUE).filter((f) => f.endsWith(".json")).length);
  console.log("results :", fs.readdirSync(RESULTS).length);
  process.exit(0);
}

if (!serving) { banner(process.stderr); die(`unknown command: ${cmd}（try help）`); }
