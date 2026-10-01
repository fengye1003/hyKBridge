#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
hyKBridge-pulse.py -- the DEVICE side of the rendezvous.

The device is the active party: it wakes on an RTC alarm, finds the host on the
LAN, and pulls a command. The host's HTTP response body IS the command.

Security rule that matters most: every response is signed by the host with
    X-Host-Sig = HMAC-SHA256(secret, body)
and we VERIFY it before doing anything. Commands run as root on this device, so a
rogue "host" on the LAN is the real threat -- an unsigned or mis-signed body is
discarded, never executed. (Responses from /file/ are signed over sha256(data).)

Never suspends while you are reading: it takes over the suspend itself (rtcwake) only
once the screen is already off, because a suspend powerd starts on its own is never woken
by an alarm we armed beforehand (measured -- see sleep_until_next_cycle). If wireless is
off (airplane mode) it short-circuits: no poll, no alarm, no wake.
"""
from __future__ import print_function

import base64
import hashlib
import hmac
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

DIR = '/mnt/us/extensions/hyKBridge'
STATE = os.path.join(DIR, 'state')
LOG = os.path.join(STATE, 'pulse.log')
OUTBOX = os.path.join(STATE, 'outbox')
PAIRED = os.path.join(STATE, 'paired.json')
FLAG = os.path.join(STATE, 'pulse-on')
RTC = '/sys/class/rtc/rtc0/wakealarm'
DOCS = '/mnt/us/documents'
BEACON_PORT = 8093
CMD_TIMEOUT = 90


def log(msg):
    line = '%s %s' % (time.strftime('%Y-%m-%d %H:%M:%S'), msg)
    try:
        with open(LOG, 'a') as f:
            f.write(line + '\n')
    except IOError:
        pass
    print('[i] ' + msg)


def eips(row, text):
    try:
        subprocess.call(['eips', '2', str(row), str(text)[:50]])
    except Exception:
        pass


def sh(cmd, cwd='/mnt/us', timeout=CMD_TIMEOUT):
    """Run a command, bounded by timeout(1) if it exists."""
    full = cmd
    if os.path.exists('/usr/bin/timeout') or os.path.exists('/bin/timeout'):
        full = 'timeout -t %d sh -c %s' % (timeout, _q(cmd))
    else:
        full = 'sh -c %s' % _q(cmd)
    p = subprocess.Popen(full, shell=True, cwd=cwd,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = p.communicate()
    return p.returncode, _dec(out) + _dec(err)


def _q(s):
    return "'" + s.replace("'", "'\\''") + "'"


def _dec(b):
    return b.decode('utf-8', 'replace') if b else ''


def power_state():
    return sh('lipc-get-prop com.lab126.powerd state')[1].strip().lower()


# ★ powerd states that mean "the screen is off", i.e. safe for us to take the suspend.
#   `active` is the ONLY state where the user is holding a lit device -- that is reading.
#
#   `readytosuspend` is the one that bit us (measured 2026-10-01, cost 29 minutes of dead
#   air and a queued book): it means powerd is about to suspend the device itself, and it
#   is ALSO what powerd reports for a while right after one of our own rtcwake resumes while
#   the screen is still off. Cycle 3 woke at 15:25:50, read `readytosuspend` at 15:26:15,
#   did not recognise it, assumed "the user must be reading", and went back to a 180 s wait.
#   powerd suspended inside that window -- and a powerd-owned suspend ignores an alarm we
#   armed beforehand, so nothing woke the device until the power button was pressed at
#   15:55. The screen was off the whole time; the state name just never matched.
SCREEN_OFF_STATES = ('screensaver', 'ready', 'readytosuspend')


def screen_is_off(state=None):
    return (state if state is not None else power_state()) in SCREEN_OFF_STATES


def wait_for_network(timeout=45):
    """Wait until wlan0 actually has an IP.

    Measured 2026-10-01: right after a resume the WiFi needs several seconds to
    associate. Cycle 2 in the field ran 4 seconds after the device was woken by hand,
    found no host, and silently did nothing -- the queued job was never fetched.
    """
    end = time.time() + timeout
    while time.time() < end:
        rc, out = sh("ifconfig wlan0 2>/dev/null | grep -c 'inet addr'")
        if out.strip().startswith('1'):
            return True
        time.sleep(3)
    log('  WARNING: wlan0 has no IP after %ds -- polling anyway' % timeout)
    return False


def sleep_until_next_cycle(cycle, interval):
    """Suspend until the next cycle -- with rtcwake, which is the only thing that works.

    ★ Measured 2026-10-01, and this is why the job queue sat untouched for 4.4 hours:
      writing `+900` into /sys/class/rtc/rtc0/wakealarm *reads back correctly* (the kernel
      converts it to a proper epoch) and /proc/driver/rtc shows the alarm set -- but the
      device NEVER woke: the pulse process stayed frozen and not one cycle was logged.
      `rtcwake -d /dev/rtc0 -m mem -s 60` suspends and comes back reliably, because it
      sets the alarm through the RTC ioctl and owns the suspend itself.

    Guard: only suspend when the screen is already off (see SCREEN_OFF_STATES). If the user
    is reading -- state `active` -- we just wait; using the device is never interrupted.
    """
    st = power_state()
    if not screen_is_off(st):
        # The user is reading: never suspend, but do keep syncing every few minutes --
        # the CPU and WiFi are on anyway, so a poll costs almost nothing and cannot
        # disturb reading (no screen writes, one small HTTP request).
        # Kept tight (120 s, not 300 s) on purpose: if powerd ever mis-reports a lit device
        # as idle we want to be back to check before its ~2 min path to suspend completes.
        awake = int(read_state('pulse-interval-awake', '120') or 120)
        log('cycle %d: awake (powerd=%s) -- not suspending; next poll in %ds' % (cycle, st or '?', awake))
        wait_wakeable(awake, cycle)
        return
    if os.path.exists('/usr/sbin/rtcwake'):
        # explicit timeout: sh() wraps commands with timeout(1), and the default would
        # kill rtcwake long before the alarm fires
        sh('sync')
        rc, out = sh('/usr/sbin/rtcwake -d /dev/rtc0 -m mem -s %d' % interval, timeout=interval + 300)
        log('cycle %d: rtcwake -m mem -s %d returned rc=%s -- awake again' % (cycle, interval, rc))
        return
    # Fallback (no rtcwake on this build): arm by hand, then suspend. Kept so an older
    # device still limps along; on this PW3 the hand-armed alarm does NOT wake it.
    alarm = arm_alarm(interval)
    if not alarm:
        log('cycle %d: no alarm armed -- NOT suspending (it would never wake)' % cycle)
        wait_wakeable(interval, cycle)
        return
    log('cycle %d: alarm=%s (no rtcwake available) -- suspending by hand' % (cycle, alarm))
    sh('sync; echo mem > /sys/power/state')


def wait_wakeable(secs, cycle):
    """Wait, but return the moment either (a) the screen goes off, or (b) we were woken.

    Agreed behaviour (user, 2026-10-01): sync on every manual wake, and every few minutes
    while awake, without loading the device or disturbing reading. And -- the important
    one -- the device must still wake ITSELF after the user simply lets it fall into the
    screen saver. The user's only sleep path IS the screen saver; suspending the device
    from a shell is something they will never do, so it must not be a precondition.

    Why (a) matters: powerd takes roughly two minutes from screen-off to actually
    suspending, and a suspend that powerd initiates is NOT woken by an alarm we armed
    beforehand (measured). So as soon as the screen goes off we hand over to the
    alarm-driven sleep ourselves, well inside that two-minute window; from then on the
    wake-ups are ours. The screen check runs every 15 s -- one tiny lipc call, and it keeps
    a large margin before powerd's own suspend.

    Why (b) matters: if powerd did get there first, a 3 s sleep that took more than 30 s of
    wall time can only mean we were suspended, so we poll right away instead of finishing a
    long wait (this is also the "sync as soon as a human wakes it" case).
    """
    deadline = time.time() + secs
    last = time.time()
    last_check = 0.0
    while os.path.exists(FLAG) and time.time() < deadline:
        time.sleep(3)
        now = time.time()
        if now - last > 30:
            log('cycle %d: resumed from a powerd-owned suspend -- polling right away' % cycle)
            return
        last = now
        if now - last_check >= 15:
            last_check = now
            st = power_state()
            if screen_is_off(st):
                log('cycle %d: screen went off (powerd=%s) -- taking over the suspend now' % (cycle, st))
                return


def read_state(name, default=None):
    try:
        with open(os.path.join(STATE, name)) as f:
            v = f.read().strip()
        return v or default
    except IOError:
        return default


def load_paired():
    try:
        with open(PAIRED) as f:
            return json.load(f)
    except Exception:
        return {}


def wireless_off():
    """Airplane mode / wireless off => short circuit.

    Judged by the explicit switch, NOT wlan0's operstate: right after resume wlan0
    is not re-associated yet, and reading that as 'airplane mode' would mean we
    never arm another alarm and never wake again.
    """
    try:
        out = subprocess.check_output(['lipc-get-prop', 'com.lab126.wifid', 'enable'],
                                      stderr=subprocess.STDOUT)
        return out.decode().strip() == '0'
    except Exception:
        return False


def keep_awake(on):
    """Set/clear the runtime keep-awake property (com.lab126.powerd.preventScreenSaver).

    NOT called by the poll loop any more -- see the comment in main(): doing this once
    per cycle kept the device permanently awake (the idle timer was reset every ~140 s,
    so it never reached the screen saver and never suspended). Kept here because it is
    the exact same two-line lipc call the shell tooling (keepawake.sh / start.sh) makes,
    and because a future caller might legitimately need it for a long transfer.
    """
    try:
        subprocess.call(['lipc-set-prop', 'com.lab126.powerd', 'preventScreenSaver',
                         '1' if on else '0'])
    except Exception:
        pass


def arm_alarm(seconds):
    try:
        with open(RTC, 'w') as f:
            f.write('0')
        with open(RTC, 'w') as f:
            f.write('+%d' % seconds)
        with open(RTC) as f:
            return f.read().strip()
    except Exception:
        return ''


# ── host discovery ───────────────────────────────────────────────
def hello(ip, port, timeout=3):
    try:
        r = urllib.request.urlopen('http://%s:%d/__hello' % (ip, port), timeout=timeout)
        j = json.loads(r.read().decode('utf-8'))
        if j.get('app') == 'hyKBridge':
            return j
    except Exception:
        pass
    return None


def find_host(rec):
    """1) the remembered address  2) the UDP beacon.  (LAN only, short timeouts.)"""
    ip = rec.get('host_ip')
    ports = rec.get('ports') or [8091, 8092]
    if ip:
        for p in ports:
            if hello(ip, p):
                return ip, p
    # beacon: the host broadcasts its address every 2s
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.settimeout(6)
    try:
        s.bind(('', BEACON_PORT))
        t0 = time.time()
        while time.time() - t0 < 6:
            data, addr = s.recvfrom(1024)
            txt = data.decode('utf-8', 'replace')
            if not txt.startswith('HYKBRIDGE1 '):
                continue
            try:
                j = json.loads(txt[11:])
            except ValueError:
                continue
            p = int(j.get('port') or 0)
            if p and hello(addr[0], p, 2):
                log('found host by beacon: %s:%d' % (addr[0], p))
                return addr[0], p
    except socket.timeout:
        pass
    except Exception:
        pass
    finally:
        s.close()
    return None, None


def remember(rec, ip, port):
    """Update the remembered address (the host never has to be configured by hand)."""
    all_paired = load_paired()
    dev = rec.get('device_id')
    if dev and dev in all_paired:
        all_paired[dev]['host_ip'] = ip
        tmp = PAIRED + '.tmp'
        with open(tmp, 'w') as f:
            json.dump(all_paired, f, indent=1)
        os.remove(PAIRED)
        os.rename(tmp, PAIRED)


def sign(secret, dev, method, path, ts=None):
    ts = ts or int(time.time())
    msg = '|'.join([dev, str(ts), method, path]).encode('utf-8')
    return {'X-Dev': dev, 'X-Ts': str(ts),
            'X-Sig': hmac.new(secret.encode('utf-8'), msg, hashlib.sha256).hexdigest()}


def get(rec, ip, port, path, timeout):
    req = urllib.request.Request('http://%s:%d%s' % (ip, port, path))
    for k, v in sign(rec['secret'], rec['device_id'], 'GET', path.split('?')[0]).items():
        req.add_header(k, v)
    try:
        r = urllib.request.urlopen(req, timeout=timeout)
        return r.getcode(), r.read(), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read(), dict(e.headers)
    except Exception as e:
        return 0, str(e).encode(), {}


def post_result(rec, ip, port, job, text):
    path = '/result'
    body = text.encode('utf-8')
    req = urllib.request.Request('http://%s:%d%s?job=%s' % (ip, port, path, job), data=body)
    req.add_header('Content-Type', 'text/plain; charset=utf-8')
    for k, v in sign(rec['secret'], rec['device_id'], 'POST', path).items():
        req.add_header(k, v)
    try:
        urllib.request.urlopen(req, timeout=15).read()
        return True
    except Exception as e:
        log('post result failed: %s' % e)
        return False


def verify(secret, body, sig):
    if not sig:
        return False
    want = hmac.new(secret.encode('utf-8'), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(want, sig)


# ── one cycle ────────────────────────────────────────────────────
def do_cycle(rec, interval):
    ip, port = find_host(rec)
    if not ip:
        log('no host found this cycle (remembered %s, no beacon)' % rec.get('host_ip'))
        return
    remember(rec, ip, port)

    path = '/next?dev=%s&hold=20' % rec['device_id']
    code, body, hdrs = get(rec, ip, port, path, timeout=30)
    if code == 204 or code == 0:
        return
    if code != 200:
        log('next -> HTTP %s' % code)
        return

    sig = hdrs.get('X-Host-Sig') or hdrs.get('x-host-sig')
    if not verify(rec['secret'], body, sig):
        log('*** SIGNATURE MISMATCH from %s -- refusing to execute ***' % ip)
        eips(3, 'hyKBridge: bad host signature')
        return

    job = hdrs.get('X-Job-Id') or hdrs.get('x-job-id') or 'unknown'
    jtype = (hdrs.get('X-Job-Type') or hdrs.get('x-job-type') or 'exec').lower()

    if jtype == 'file':
        try:
            meta = json.loads(body.decode('utf-8'))
        except ValueError:
            log('bad file job payload for %s' % job)
            return
        name = os.path.basename(meta.get('name') or 'book.bin')
        fcode, data, fh = get(rec, ip, port, '/file/%s' % job, timeout=120)
        fsig = fh.get('X-Host-Sig') or fh.get('x-host-sig')
        if fcode != 200 or not data:
            log('file %s download failed (HTTP %s)' % (name, fcode))
            return
        want = hmac.new(rec['secret'].encode('utf-8'),
                        hashlib.sha256(data).hexdigest().encode('utf-8'),
                        hashlib.sha256).hexdigest()
        if not hmac.compare_digest(want, fsig or ''):
            log('*** FILE SIGNATURE MISMATCH for %s -- not writing ***' % name)
            return
        dest = os.path.join(DOCS, name)
        tmp = dest + '.hykbridge-part'
        with open(tmp, 'wb') as f:
            f.write(data)
        if os.path.exists(dest):
            os.remove(dest)
        os.rename(tmp, dest)
        log('file %s saved (%d bytes)' % (name, len(data)))
        post_result(rec, ip, port, job, 'rc=0\nsaved to %s\nbytes=%d\n' % (dest, len(data)))
        return

    # exec: the body IS the command
    cmd = body.decode('utf-8', 'replace')
    log('job %s exec: %s' % (job, cmd.split('\n')[0][:80]))
    rc, out = sh(cmd)
    text = 'rc=%d\ncmd=%s\n--- output ---\n%s\n' % (rc, cmd, out)
    # persist first: if the host vanished mid-flight we still owe it an answer
    if not os.path.isdir(OUTBOX):
        os.makedirs(OUTBOX)
    with open(os.path.join(OUTBOX, job + '.txt'), 'w') as f:
        f.write(text)
    if post_result(rec, ip, port, job, text):
        try:
            os.remove(os.path.join(OUTBOX, job + '.txt'))
        except OSError:
            pass
    log('job %s done rc=%d' % (job, rc))


def deliver_outbox(rec, ip, port):
    if not os.path.isdir(OUTBOX):
        return
    for fn in sorted(os.listdir(OUTBOX)):
        if not fn.endswith('.txt'):
            continue
        p = os.path.join(OUTBOX, fn)
        try:
            with open(p) as f:
                text = f.read()
            if post_result(rec, ip, port, fn[:-4], text):
                os.remove(p)
                log('outbox: delivered %s' % fn[:-4])
        except Exception:
            pass


def main():
    if not os.path.exists(FLAG):
        log('pulse-on flag missing -- nothing to do')
        return 0
    paired = load_paired()
    if not paired:
        log('no paired host -- run KUAL > hyKBridge > Show Pairing Code first')
        eips(3, 'hyKBridge: not paired yet')
        return 1
    dev, rec = list(paired.items())[0]
    rec['device_id'] = rec.get('device_id') or dev
    if 'secret' not in rec:
        log('paired record has no secret')
        return 1

    # Interval = how often the device wakes up to poll. Now that the loop OWNS the suspend
    # (rtcwake), this is a plain latency/battery trade-off -- it no longer decides *whether*
    # the device can sleep at all. (An earlier version armed the alarm by hand and let powerd
    # suspend on its own; measured 2026-10-01, a powerd-initiated suspend NEVER honours a
    # pre-armed alarm: the device slept 4.4 hours with zero cycles. See sleep_until_next_cycle.)
    # Cost per wake = WiFi re-association + a few seconds of CPU. 300 s (5 min) is the shipped
    # default: now that the loop owns the suspend, the interval is pure latency -- nobody wants
    # a book pushed by mail to wait a quarter of an hour. Raise it to save battery.
    interval = int(read_state('pulse-interval', '300') or 300)
    log('== HyKBridge by HYrecovery & HoshinoSumi from teko.IO SisTemS! ==')
    log('== Under MIT Open Source License ==')
    log('pulse START interval=%ds host=%s (owns the suspend via rtcwake when the screen is off)' % (interval, rec.get('host_ip')))
    eips(3, 'hyKBridge pulse: every %ds' % interval)

    cycle = 0
    while os.path.exists(FLAG):
        cycle += 1
        if wireless_off():
            try:
                with open(RTC, 'w') as f:
                    f.write('0')
            except Exception:
                pass
            log('cycle %d: wireless OFF (airplane mode) -> short circuit' % cycle)
            while os.path.exists(FLAG) and wireless_off():
                time.sleep(15)
            continue

        # ★ DON'T touch preventScreenSaver here (2026-10-01 fix).
        # The first version wrapped every cycle in keep_awake(True)/keep_awake(False)
        # to "hold the window open while we talk". Measured consequence on the real
        # device: powerd logged "Prevent screen saver set, value = 1" then "= 0" once
        # per cycle (~140 s), each pair resetting the idle timer (t1TimerReset) -- so
        # the device NEVER reached screen saver and never suspended. Battery fell
        # 92% -> 87% in a day with the device just sitting there. It also clobbered a
        # user-enabled keep-awake every cycle (keep_awake(False)).
        #
        # It is not needed: a poll takes seconds, while the screen saver needs minutes
        # of idle time, so a cycle can never be interrupted by a suspend. If the user
        # WANTS the device held awake, that is the opt-in state/keep-awake flag's job
        # (keepawake.sh on / start.sh), not the poll loop's.
        # After a resume the WiFi needs a few seconds to re-associate; polling immediately
        # is why cycle 2 in the field found no host and silently did nothing.
        wait_for_network(45)
        ip, port = find_host(rec)
        if ip:
            remember(rec, ip, port)
            deliver_outbox(rec, ip, port)
            do_cycle(rec, interval)
        else:
            # Say it out loud: silence here is how "the queue sat untouched for an hour"
            # stayed invisible -- a failed discovery used to produce no log line at all.
            log('cycle %d: host NOT found (no network? wifi down?) -- nothing polled' % cycle)

        if not os.path.exists(FLAG):
            break
        # OWN the suspend. Measured 2026-10-01: if powerd is allowed to suspend the device
        # by itself, a pre-armed alarm is never honoured (4.4 hours asleep, zero cycles);
        # when the suspend is initiated here, the alarm always fires. See sleep_until_next_cycle().
        sleep_until_next_cycle(cycle, interval)

    log('pulse STOP')
    eips(3, 'hyKBridge pulse: stopped')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(0)
