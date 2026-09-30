#!/usr/bin/env node
/*
 * selftest.mjs — protocol test for the host side. Plays the DEVICE's role with a
 * simulated client, so the whole handshake can be verified without a Kindle:
 *
 *   1. /__hello is open and identifies the app
 *   2. /next without credentials        -> 401
 *   3. /next with a stale timestamp     -> 401   (replay protection)
 *   4. /next with a wrong secret        -> 401   (rogue device)
 *   5. /next with no job, hold=4        -> 204 after ~4s (long-poll actually holds)
 *   6. after enqueue: body IS the command, and X-Host-Sig verifies
 *   7. a tampered body fails signature verification (this is what protects the
 *      device from a rogue host feeding it root commands)
 *   8. POST /result stores the output and clears the job
 *
 *   node selftest.mjs
 */
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const HOME = path.join(HERE, ".selftest-home");
const PORT = 8099;
const DEV = "dev-" + "a".repeat(12);
const SECRET = "s".repeat(64);
const hmac = (s, d) => crypto.createHmac("sha256", s).update(d).digest("hex");

console.log([
  "== HyKBridge by HYrecovery & HoshinoSumi from teko.IO SisTemS! ==",
  "== Under MIT Open Source License =="
].join("\n"));

let pass = 0, fail = 0;
const check = (name, cond, detail = "") => {
  (cond ? pass++ : fail++);
  console.log(`  ${cond ? "[OK]" : "[NG]"} ${name}${detail ? "  " + detail : ""}`);
};

fs.rmSync(HOME, { recursive: true, force: true });
fs.mkdirSync(path.join(HOME, "queue"), { recursive: true });
fs.mkdirSync(path.join(HOME, "results"), { recursive: true });
fs.writeFileSync(path.join(HOME, "host.json"), JSON.stringify({
  host_id: "host-test", name: "test-host", ports: [PORT],
  paired: { [DEV]: { name: "sim-device", secret: SECRET, paired_at: Date.now() } }
}, null, 2));

// NOTE: stdio MUST NOT be "pipe" here -- this sandbox rejects piped stdio with
// EPERM (named pipes are blocked). Use "ignore" and let the server log to a file.
const srvLog = path.join(HOME, "server.log");
const logFd = fs.openSync(srvLog, "a");
const proc = spawn(process.execPath, [path.join(HERE, "hyKBridge.mjs"), "serve", "--port", String(PORT)],
  { env: { ...process.env, HYKBRIDGE_HOME: HOME, HYKBRIDGE_BEACON: "8094" }, stdio: ["ignore", logFd, logFd] });

const base = `http://127.0.0.1:${PORT}`;
const auth = (ts, secret = SECRET, method = "GET", p = "/next") =>
  ({ "X-Dev": DEV, "X-Ts": String(ts), "X-Sig": hmac(secret, [DEV, String(ts), method, p].join("|")) });

await new Promise((r) => setTimeout(r, 900));

try {
  // 1
  const hello = await fetch(`${base}/__hello`);
  const hj = await hello.json();
  check("/__hello is open and identifies the app", hello.status === 200 && hj.app === "hyKBridge",
    `host_id=${hj.host_id} paired=${hj.paired}`);

  // 2
  let r = await fetch(`${base}/next?dev=${DEV}`);
  check("no credentials -> 401", r.status === 401);

  // 3
  const oldTs = Math.floor(Date.now() / 1000) - 999;
  r = await fetch(`${base}/next?dev=${DEV}`, { headers: auth(oldTs) });
  check("stale timestamp -> 401 (replay protection)", r.status === 401);

  // 4
  const now = Math.floor(Date.now() / 1000);
  r = await fetch(`${base}/next?dev=${DEV}`, { headers: auth(now, "x".repeat(64)) });
  check("wrong secret -> 401 (rogue device)", r.status === 401);

  // 5 long-poll holds
  const t0 = Date.now();
  r = await fetch(`${base}/next?dev=${DEV}&hold=4`, { headers: auth(Math.floor(Date.now() / 1000)) });
  const held = (Date.now() - t0) / 1000;
  check("empty queue + hold=4 -> 204 after ~4s", r.status === 204 && held >= 3.5 && held < 7,
    `held ${held.toFixed(1)}s`);

  // 6 enqueue then pull; body is the command and the signature verifies
  const { execSync } = await import("node:child_process");
  execSync(`"${process.execPath}" "${path.join(HERE, "hyKBridge.mjs")}" exec "echo hello-from-host; id"`,
    { env: { ...process.env, HYKBRIDGE_HOME: HOME }, stdio: "ignore" });

  r = await fetch(`${base}/next?dev=${DEV}&hold=5`, { headers: auth(Math.floor(Date.now() / 1000)) });
  const body = await r.text();
  const sig = r.headers.get("x-host-sig");
  const jobId = r.headers.get("x-job-id");
  check("body IS the queued command", r.status === 200 && body === "echo hello-from-host; id", JSON.stringify(body));
  check("X-Host-Sig verifies with the shared secret",
    !!sig && crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(hmac(SECRET, body))));

  // 7 tampered body must not verify
  check("tampered body fails verification",
    !crypto.timingSafeEqual(Buffer.from(hmac(SECRET, body + "; rm -rf /")), Buffer.from(sig)));

  // 8 post the result
  r = await fetch(`${base}/result?job=${jobId}&dev=${DEV}&ts=${Math.floor(Date.now() / 1000)}`, {
    method: "POST",
    headers: { ...auth(Math.floor(Date.now() / 1000), SECRET, "POST", "/result"), "Content-Type": "text/plain" },
    body: "rc=0\n--- output ---\nuid=0(root)\n"
  });
  const stored = path.join(HOME, "results", jobId + ".txt");
  check("POST /result stores the output", r.status === 200 && fs.existsSync(stored)
    && fs.readFileSync(stored, "utf8").includes("uid=0(root)"));
  check("job removed from the queue after its result arrived",
    !fs.existsSync(path.join(HOME, "queue", jobId + ".json.taken"))
    && !fs.existsSync(path.join(HOME, "queue", jobId + ".json")));
} finally {
  proc.kill();
  await new Promise((r) => setTimeout(r, 300));
}

console.log("");
console.log(`RESULT: ${pass} passed, ${fail} failed`);
if (fail) { console.log("--- server log ---\n" + (fs.existsSync(srvLog) ? fs.readFileSync(srvLog,"utf8") : "")); process.exit(1); }
process.exit(0);
