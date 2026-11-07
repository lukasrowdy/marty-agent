"""Separate host process: cut fixed VM power on pipe loss, stale pulse or deadline."""
import queue
import sys
import threading
import time
from jr_emergency_stop import cut_off

events=queue.Queue()
def read():
    try:
        for line in sys.stdin.buffer:
            if line==b'heartbeat\n': events.put(time.monotonic())
    finally: events.put(None)
threading.Thread(target=read,daemon=True).start()
deadline=time.monotonic()+15*60
last=time.monotonic()
while time.monotonic()<deadline:
    try: stamp=events.get(timeout=max(.01,min(1,12-(time.monotonic()-last))))
    except queue.Empty:
        if time.monotonic()-last>=12: break
        continue
    if stamp is None: break
    last=stamp
cut_off()
