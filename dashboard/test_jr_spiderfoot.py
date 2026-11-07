import os
from pathlib import Path
import json
import subprocess
import sys
import time
os.environ['MARTY_AGENT_ROOT'] = 'C:/Users/{{WIN_USER}}/my-agent'
sys.path.insert(0, str(Path(__file__).parent))
import jr_spiderfoot as s
import jr_tools

def wait(job, seconds=30):
    end = time.monotonic() + seconds
    while job['state'] == 'running' and time.monotonic() < end:
        time.sleep(.1)
    assert job['state'] != 'running', job

def process_map():
    r = subprocess.run(['powershell.exe', '-NoProfile', '-Command', 'Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId | ConvertTo-Json -Compress'], capture_output=True, text=True, check=True)
    return {r['ProcessId']: r['ParentProcessId'] for r in json.loads(r.stdout)}

def refuses(fn):
    try:
        fn()
    except s.ScanError:
        return
    raise AssertionError('not refused')

m = s.MANAGER
catalog = s.modules()
assert len(catalog) == 233 and any(x['module'] == 'sfp_crt' and x['name'] == 'Certificate Transparency' for x in catalog)
print('PASS installed module metadata', flush=True)
for v in ['example.com', 'test@example.com', 'Sample Person', 'sample_username', '+12025550123', '1234', '2001:db8::1', '192.0.2.0/24']:
    assert s.target(v) == v
for v in ['-l', '../path', 'a\nb', 'x;echo', 'https://example.com']:
    refuses(lambda v=v: s.target(v))
refuses(lambda: m.call('a', 't', m.epoch, {'action':'start','target':'example.com','modules':['../bad']}))
assert jr_tools.Toolbox().run('spiderfoot', {'action':'status'}).status == 'refused'
print('PASS standard target types, argument checks, authenticated-context requirement', flush=True)

jv=m.call('a','t',m.epoch,{'action':'start','target':'example.com','modules':['sfp_crt']})
j=m.jobs[jv['scan_id']]
refuses(lambda: m.call('b','t',m.epoch,{'action':'results','scan_id':j['scan_id']}))
refuses(lambda: m.call('b','t',m.epoch,{'action':'stop','scan_id':j['scan_id']}))
refuses(lambda: m.call('a','t',m.epoch,{'action':'start','target':'example.com'}))
assert not m.call('b','t',m.epoch,{'action':'status'})['scans']
time.sleep(3)
pm = process_map()
children={j.get('pid')}
for _ in range(5):
    children |= {pid for pid,parent in pm.items() if parent in children}
m.call('a','t',m.epoch,{'action':'stop','scan_id':j['scan_id']})
wait(j)
assert j['state']=='cancelled',j
assert not (s.RUNTIME/j['scan_id']).exists(),j
assert not (children & process_map().keys()),children
print('PASS owner isolation, one-scan limit, cancellation kills process tree and removes files',flush=True)

old=s.SECONDS
s.SECONDS=.3
jv=m.call('a','t',m.epoch,{'action':'start','target':'example.com','modules':['sfp_crt']})
j=m.jobs[jv['scan_id']]
wait(j)
assert j['state']=='timed_out',j
assert not (s.RUNTIME/j['scan_id']).exists()
s.SECONDS=old
print('PASS timeout terminates worker and removes files',flush=True)

old_epoch=m.epoch
jv=m.call('a','t',m.epoch,{'action':'start','target':'example.com','modules':['sfp_crt']})
j=m.jobs[jv['scan_id']]
time.sleep(.5)
m.clear()
assert not m.jobs
refuses(lambda:m.call('a','t',old_epoch,{'action':'status'}))
wait(j)
assert j['state']=='cancelled' and not m.active and not (s.RUNTIME/j['scan_id']).exists(),j
print('PASS locking clears results, invalidates old toolboxes and stops scans',flush=True)

jv=m.call('a','t',m.epoch,{'action':'start','target':'example.com','modules':['sfp_dnsresolve']})
j=m.jobs[jv['scan_id']]
wait(j,45)
assert j['state']=='completed' and j['finding_count']>0 and not j['warnings'],j
assert not (s.RUNTIME/j['scan_id']).exists()
print('PASS actual SpiderFoot completion, structured results and cleanup',flush=True)
m.clear()
print('ALL ADAPTER CHECKS PASSED',flush=True)
