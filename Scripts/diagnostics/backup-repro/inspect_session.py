#!/usr/bin/env python3
"""Print selected, non-content diagnostics from a finished root-private session."""
import argparse
import json
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('session')
a=p.parse_args()
root=Path(a.session).resolve(strict=True)
if root.parent!=Path('/private/tmp') or not root.name.startswith('NickBackupRepro-'):
    raise SystemExit('Expected a harness evidence session in /private/tmp')
def selected(h):
    return {k:h.get(k) for k in ['version','processID','updatedAt','active','authResponseErrorCount',
        'authResponseMaximumMilliseconds','eventsPerSecond','scanWorkDiagnostics','mountStartupDiagnostics']}
before=json.loads((root/'before-health.json').read_text())
after=json.loads((root/'after-health.json').read_text())
summary={'before':selected(before),'after':selected(after),'events':[],
         'result':json.loads((root/'result.json').read_text())}
for line in (root/'events.jsonl').open():
    e=json.loads(line)
    if e['kind'] in ['stage-start','stage-end','attach','detach','safety-stop','cleanup-incomplete']:
        summary['events'].append(e)
print(json.dumps(summary,indent=2))
