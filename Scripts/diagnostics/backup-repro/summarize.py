#!/usr/bin/env python3
"""Summarize one private evidence session; no workload or system calls."""
import argparse
import json
from pathlib import Path
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('session')
a = p.parse_args()
root = Path(a.session).expanduser().resolve(strict=True)
count = 0
peak = 0
cpu_sum = 0
cpu_n = 0
first = last = None
with (root/'samples.jsonl').open() as f:
    for line in f:
        r = json.loads(line)
        first = first or r
        last = r
        count += 1
        peak = max(peak, r['phys_footprint'])
        if 'cpuPercent' in r:
            cpu_sum += r['cpuPercent']
            cpu_n += 1
stages = []
runs = {}
with (root/'events.jsonl').open() as f:
    for line in f:
        e = json.loads(line)
        if e['kind'] in ['stage-start','stage-end','safety-stop','cleanup-incomplete']:
            stages.append(e)
        if e['kind'] == 'health':
            for r in e['health']['scanWorkDiagnostics'].get('usbRuns', []):
                runs[r['id']] = r
result = json.loads((root/'result.json').read_text()) if (root/'result.json').exists() else {'status':'incomplete'}
summary = {'samples':count,'first':first,'last':last,'peakSampledFootprintBytes':peak,
           'meanCPUPercent':cpu_sum/cpu_n if cpu_n else None,'stages':stages,
           'retainedUSBRecords':list(runs.values()),'result':result,
           'interpretation':'Descriptive evidence only; no automatic root-cause or protection PASS claim. Kernel peaks may predate stage. USB records are not volume-attributed.'}
(root/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
print(root/'summary.json')
