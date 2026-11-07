"""
hf_batch.py - run a list of Higgsfield generation jobs, download every result into a
project folder, and keep a one-line record per job (model, prompt, credits, job id).

    py -3 tools/hf_batch.py <jobs.json> <outdir>

jobs.json is a list of objects:
    {"name": "byte-sheet", "model": "nano_banana_pro", "prompt": "...",
     "args": ["--aspect_ratio", "3:4"], "media": {"--image-references": ["path1.png", ...]}}

Each job runs `higgsfield generate create <model> --prompt ... <args> --wait --json`,
then every URL in the returned JSON that looks like a media file is downloaded to
<outdir>/<name>[-N].<ext>. The record goes to <outdir>/RECORD.md. The raw JSON is
kept in <outdir>/_json/<name>.json for retrospection. Nothing here posts anywhere.

House rule (vault Job note "Higgsfield Image and Video Generation"): estimate with
`higgsfield generate cost` first and get Lukas's yes before running this.
"""

import json
import pathlib
import re
import subprocess
import sys
import time
import urllib.request

HF = r"C:\Users\{{WIN_USER}}\AppData\Roaming\npm\higgsfield.cmd"
MEDIA_RE = re.compile(r'https?://[^\s"\']+\.(?:png|jpe?g|webp|mp4|mov|webm|mp3|wav|glb)(?:\?[^\s"\']*)?', re.I)


def find_urls(obj, out):
    if isinstance(obj, dict):
        for v in obj.values():
            find_urls(v, out)
    elif isinstance(obj, list):
        for v in obj:
            find_urls(v, out)
    elif isinstance(obj, str):
        for m in MEDIA_RE.finditer(obj):
            u = m.group(0)
            if u not in out:
                out.append(u)


def find_key(obj, keys):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in keys and isinstance(v, (str, int, float)):
                return v
        for v in obj.values():
            r = find_key(v, keys)
            if r is not None:
                return r
    elif isinstance(obj, list):
        for v in obj:
            r = find_key(v, keys)
            if r is not None:
                return r
    return None


def main():
    jobs = json.load(open(sys.argv[1], encoding="utf-8"))
    out = pathlib.Path(sys.argv[2]); (out / "_json").mkdir(parents=True, exist_ok=True)
    rec = out / "RECORD.md"
    if not rec.exists():
        rec.write_text("# Generation record\n\nOne line per job: time, name, model, credits, job id, files. Prompts in _json/.\n\n", encoding="utf-8")
    for j in jobs:
        name, model, prompt = j["name"], j["model"], j["prompt"]
        cmd = [HF, "generate", "create", model, "--prompt", prompt] + j.get("args", [])
        for flag, paths in (j.get("media") or {}).items():
            for p in paths:
                cmd += [flag, p]
        cmd += ["--wait", "--wait-timeout", "15m", "--json"]
        t0 = time.time()
        print(f"[{time.strftime('%H:%M:%S')}] {name}: {model} ...", flush=True)
        r = subprocess.run(cmd, capture_output=True, text=True)
        raw = r.stdout.strip()
        (out / "_json" / f"{name}.json").write_text(json.dumps({"cmd": cmd, "stdout": raw, "stderr": r.stderr[-3000:], "rc": r.returncode}, indent=2), encoding="utf-8")
        if r.returncode != 0 or not raw:
            print(f"   FAILED rc={r.returncode}: {r.stderr.strip()[-400:]}", flush=True)
            rec.open("a", encoding="utf-8").write(f"- {time.strftime('%Y-%m-%d %H:%M')} | {name} | {model} | FAILED | {r.stderr.strip()[-200:]}\n")
            continue
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            data = {"stdout": raw}
        urls = []; find_urls(data, urls)
        credits = find_key(data, {"credits", "cost", "credits_spent", "price"})
        job_id = find_key(data, {"id", "job_id", "job_set_id"})
        files = []
        for i, u in enumerate(urls):
            ext = re.search(r'\.(png|jpe?g|webp|mp4|mov|webm|mp3|wav|glb)', u, re.I).group(1).lower()
            fn = out / (f"{name}.{ext}" if len(urls) == 1 else f"{name}-{i+1}.{ext}")
            try:
                urllib.request.urlretrieve(u, fn); files.append(fn.name)
            except Exception as e:  # noqa: BLE001
                print(f"   download failed: {e}", flush=True)
        status = find_key(data, {"status"})
        print(f"   done in {time.time()-t0:.0f}s, status={status}, credits={credits}, files={files or urls[:1]}", flush=True)
        rec.open("a", encoding="utf-8").write(f"- {time.strftime('%Y-%m-%d %H:%M')} | {name} | {model} | credits {credits} | job {job_id} | {', '.join(files) or 'NO FILE (see _json)'}\n")
    print("batch complete", flush=True)


if __name__ == "__main__":
    main()
