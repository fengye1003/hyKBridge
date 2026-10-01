// Watch the Kindle's pulse log until the wake loop is PROVEN, then say so.
//
// Why a dedicated watcher: on 2026-10-01 the loop looked healthy for two cycles and then
// silently lost the suspend race -- powerd suspended, nothing woke the device, and a queued
// book sat for 29 minutes. The only thing that proves the fix is *consecutive self-wakes
// while nobody touches the device*, so this samples until it has them.
//
//   node host/watch-sleep.mjs [--minutes 60] [--need 3] [--interval 300] [--poll 60000]
//
// ★ SET --poll SHORTER THAN THE DEVICE'S AWAKE WINDOW. Each cycle the device is only awake
//   for ~20-40 s (long-poll + wifi re-association) out of every --interval seconds, and this
//   watcher reads the device through the DIRECT channel -- which only answers while it is
//   awake. The default 60 s poll catches those windows; an earlier 180 s poll mostly did not,
//   and printed a run of "device asleep" for a device that was in fact waking perfectly on
//   schedule (the on-device log proved it afterwards). A missed probe is NOT evidence of a
//   missed wake -- that is what the FAIL rules below are for.
//
// PASS  >= --need rtcwake cycles after the last START, every gap within the interval,
//       and no "resumed from a powerd-owned suspend" in that run (that line means powerd
//       won the race, which is exactly the failure).
// FAIL  a cycle-to-cycle gap longer than interval + 180 s, or a powerd-owned resume.
// STOP  prints the timeline either way; the caller decides.
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CLI = path.join(HERE, 'hyKBridge.mjs');

const arg = (name, dflt) => {
  const i = process.argv.indexOf('--' + name);
  return i >= 0 && process.argv[i + 1] ? Number(process.argv[i + 1]) : dflt;
};
const MINUTES = arg('minutes', 60);
const NEED = arg('need', 3);
const INTERVAL = arg('interval', 300);
const POLL_MS = arg('poll', 180_000); // default 3 min: the device is asleep most of the time,
                         // so most probes just fail harmlessly. Deliberately not 45 s -- the
                         // watcher must not be the reason the device stays awake.

const stamp = () => new Date().toTimeString().slice(0, 8);
const say = (m) => console.log(`${stamp()} ${m}`);

function run(args) {
  return new Promise((resolve) => {
    const p = spawn(process.execPath, [CLI, ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '', err = '';
    p.stdout.on('data', (d) => { out += d; });
    p.stderr.on('data', (d) => { err += d; });
    p.on('close', (code) => resolve({ code, out, err }));
  });
}

// One probe: the log tail plus the live powerd state. Uses the DIRECT channel, so it only
// answers while the device is awake -- which is exactly when a cycle could have happened.
async function probe() {
  const cmd = 'tail -40 /mnt/us/extensions/hyKBridge/state/pulse.log; '
    + 'echo "@@STATE"; lipc-get-prop com.lab126.powerd state; echo "@@DATE"; date +%s';
  const r = await run(['device', 'exec', cmd, '--json']);
  const json = r.out.trim().startsWith('{') ? JSON.parse(r.out) : null;
  if (json && json.ok && json.data) return { awake: true, out: json.data.stdout || '' };
  return { awake: false, out: r.err + r.out };
}

const CYCLE_RE = /^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) cycle (\d+): rtcwake -m mem -s (\d+) returned rc=(\d+)/;
const RESUME_RE = /^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) cycle (\d+): resumed from a powerd-owned suspend/;
const START_RE = /^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) pulse START/;
const AWAKE_RE = /^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) cycle (\d+): awake \(powerd=(\S+)\)/;

const parse = (t) => new Date(t.replace(' ', 'T')).getTime() / 1000;

const seen = new Map(); // timestamp+kind -> line
let lastState = '?';
let firstSample = null;

async function once() {
  const r = await probe();
  if (!r.awake) { say('probe: device asleep (DIRECT unreachable) -- expected between cycles'); return null; }
  if (firstSample === null) firstSample = Date.now();
  const lines = r.out.split('\n');
  const cut = lines.indexOf('@@STATE');
  const log = cut >= 0 ? lines.slice(0, cut) : lines;
  if (cut >= 0) lastState = (lines[cut + 1] || '').trim();

  for (const line of log) {
    const m = line.match(CYCLE_RE) || line.match(RESUME_RE) || line.match(START_RE) || line.match(AWAKE_RE);
    if (m) seen.set(line, line);
  }

  // Only reason about the CURRENT run: everything after the last START line.
  const all = [...seen.values()];
  let startIdx = 0;
  all.forEach((l, i) => { if (START_RE.test(l)) startIdx = i; });
  const runLines = all.slice(startIdx);

  const cycles = runLines.map((l) => l.match(CYCLE_RE)).filter(Boolean)
    .map((m) => ({ at: parse(m[1]), cycle: Number(m[2]), interval: Number(m[3]), rc: Number(m[4]), line: m[0] }));
  const badResume = runLines.find((l) => RESUME_RE.test(l));

  const gaps = [];
  for (let i = 1; i < cycles.length; i++) gaps.push(cycles[i].at - cycles[i - 1].at);
  const worst = gaps.length ? Math.max(...gaps) : 0;

  say(`probe: awake, powerd=${lastState}, self-wakes in this run: ${cycles.length}`
    + (gaps.length ? `, gaps: ${gaps.map((g) => Math.round(g)).join(', ')}s` : ''));

  if (badResume) return { verdict: 'FAIL', why: 'powerd won the suspend race: ' + badResume };
  if (worst > INTERVAL + 180) {
    return { verdict: 'FAIL', why: `a ${Math.round(worst)}s gap between self-wakes (interval ${INTERVAL}s)` };
  }
  if (cycles.length >= NEED) {
    return { verdict: 'PASS', why: `${cycles.length} consecutive self-wakes, worst gap ${Math.round(worst)}s` };
  }
  return null;
}

const deadline = Date.now() + MINUTES * 60_000;
say(`watching for ${NEED} self-wakes (interval ${INTERVAL}s, up to ${MINUTES} min)`);
say('do NOT touch the device -- its screen has to go off on its own for this to mean anything');

let result = null;
while (Date.now() < deadline && !result) {
  result = await once();
  if (result) break;
  await new Promise((s) => setTimeout(s, POLL_MS));
}

if (!result) result = { verdict: 'INCONCLUSIVE', why: 'ran out of time (was the device in use the whole time?)' };
say(`VERDICT ${result.verdict}: ${result.why}`);
say(`last powerd state seen: ${lastState}`);
process.exit(result.verdict === 'FAIL' ? 1 : 0);
