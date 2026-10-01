#!/usr/bin/env python3
"""On-device assertion for the screen-state rule that cost 29 minutes of dead air.

Runs on the Kindle, loads the deployed pulse module (import is side-effect free --
everything real is behind the __main__ guard) and asserts the classification of
every powerd state we have observed. This is deliberately a real import of the
REAL deployed file, not a copy: it proves what is on the device.
"""
import importlib.util

PATH = '/mnt/us/extensions/hyKBridge/bin/hyKBridge-pulse.py'
spec = importlib.util.spec_from_file_location('pulse', PATH)
pulse = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pulse)

EXPECT = {
    'active': False,          # screen on, the user is holding it -- never suspend
    'screensaver': True,      # screen off
    'ready': True,            # screen off, powerd would like to suspend
    'readytosuspend': True,   # ★ the one that was missing
    'suspended': False,       # we are not running here; be conservative
}

fails = 0
for state, want in sorted(EXPECT.items()):
    got = pulse.screen_is_off(state)
    ok = (got == want)
    fails += 0 if ok else 1
    print('%s %-16s -> %s (want %s)' % ('[OK]' if ok else '[NG]', state, got, want))

print('[i] screen off states: %s' % (pulse.SCREEN_OFF_STATES,))
print('[i] live powerd state: %r -> screen_is_off=%s'
      % (pulse.power_state(), pulse.screen_is_off()))
print('[i] awake interval now: %s s' % pulse.read_state('pulse-interval-awake', '120'))
print('RESULT: %d passed, %d failed' % (len(EXPECT) - fails, fails))
raise SystemExit(1 if fails else 0)
