"""Host-side cutoff for one fixed lab VM.

Independent of the model, dashboard, guest OS and guest credentials. No network
enable, VM start or arbitrary target operation exists here. Hard poweroff loses
unsaved guest work. A successful command alone is never proof of shutdown.
"""
from __future__ import annotations

import argparse
import json
import subprocess

VBOX = r'C:\Program Files\Oracle\VirtualBox\VBoxManage.exe'
VM = '{{JR_VM_UUID}}'


def _run(args, timeout):
    return subprocess.run([VBOX, *args], capture_output=True, timeout=timeout,
                          creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))


def _inspect(run):
    try:
        result = run(['showvminfo', VM, '--machinereadable'], timeout=3)
        if result.returncode:
            return 'unknown'
        values = {}
        for line in result.stdout.decode('utf-8', 'replace').splitlines():
            if '=' in line:
                key, value = line.split('=', 1)
                if key in values:
                    return 'unknown'
                values[key] = value.strip('"')
        return values.get('VMState', 'unknown')
    except Exception:
        return 'unknown'


def cut_off(run=None):
    """Request hard poweroff; on failure try pause/cable removal and retry.

    `run` is a testing seam, never populated from an HTTP/model argument.
    Per-command deadlines are not a measured end-to-end cutoff guarantee.
    """
    run = run or _run
    failed_commands = 0

    def attempt(args, timeout):
        nonlocal failed_commands
        try:
            if run(args, timeout=timeout).returncode == 0:
                return
        except Exception:
            pass
        failed_commands += 1

    # Do not wait on guest ACPI, a model reply, a dashboard lock or a preflight
    # inspection. Removing VM power also removes its running network activity.
    attempt(['controlvm', VM, 'poweroff'], 5)
    state = _inspect(run)
    if state != 'poweroff':
        attempt(['controlvm', VM, 'pause'], 2)
        # Cover every NIC even if unexpected settings were introduced. Failure
        # to inspect isolation must never prevent an emergency poweroff attempt.
        for index in range(1, 9):
            attempt(['controlvm', VM, f'setlinkstate{index}', 'off'], 1)
        attempt(['controlvm', VM, 'poweroff'], 5)
        state = _inspect(run)

    confirmed = state == 'poweroff'
    return {'poweroff_confirmed': confirmed, 'power_state': state,
            'failed_commands': failed_commands,
            'shutdown_error': None if confirmed else
                'VM power-off could not be confirmed. Jr controls are disabled. '
                'In VirtualBox, power off Jr-Computer-Lab, then retry Emergency stop VM.'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cut-off', action='store_true',
                        help='Hard power off Jr-Computer-Lab; loses unsaved guest work')
    args = parser.parse_args()
    if args.cut_off:
        result = cut_off()
        print(json.dumps(result))
        raise SystemExit(0 if result['poweroff_confirmed'] else 1)
    print(json.dumps({'inspection_only': True, 'power_state': _inspect(_run)}))
