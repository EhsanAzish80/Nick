#!/usr/bin/env python3
"""Opt-in NEXT-launch configuration, never an attach/restart/global setenv.

Default is read-only validation and a command preview. Requires an explicit
--enable-next-launch plus a verified system launchd target. System Extension
launch policies may reject this; that is a blocker, never a reason to alter SIP,
entitlements, hardened runtime or endpoint protection. Validate locally first.
"""
import argparse,json,os,pathlib,re,subprocess,sys
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('target',help='Exact system/<launchd job label> obtained locally')
p.add_argument('--enable-next-launch',action='store_true')
a=p.parse_args()
if os.geteuid()!=0:raise SystemExit('Requires sudo for system-domain inspection; default does not modify anything.')
if not re.fullmatch(r'system/[A-Za-z0-9_.-]+',a.target):raise SystemExit('Invalid system service target')
r=subprocess.run(['/bin/launchctl','print',a.target],capture_output=True,text=True,check=True,timeout=10)
match=re.search(r'^\s*program = (.+)$',r.stdout,re.M)
if not match:raise SystemExit('Cannot verify exact service executable; no configuration changed')
exe=pathlib.Path(match.group(1).strip())
pattern=r'/Library/SystemExtensions/[A-Fa-f0-9-]+/com\.ehsanazish\.nick\.NickExtension\.systemextension/Contents/MacOS/com\.ehsanazish\.nick\.NickExtension'
if not re.fullmatch(pattern,str(exe)) or not exe.is_file() or exe.stat().st_uid!=0:raise SystemExit('Target is not the root-owned Nick ES extension; nothing changed')
info=subprocess.run(['/usr/bin/codesign','-dv','--verbose=2',str(exe)],capture_output=True,text=True,check=True,timeout=10).stderr
if 'Identifier=com.ehsanazish.nick.NickExtension\n' not in info or 'TeamIdentifier=UXGW5V3BY6\n' not in info:raise SystemExit('Unexpected code identity; nothing changed')
subprocess.run(['/usr/bin/codesign','--verify','--strict',str(exe)],check=True,timeout=15)
logs=pathlib.Path('/Library/Logs/NickAllocationLogging')
command=['/bin/launchctl','debug',a.target,'--environment','MallocStackLogging=1','MallocStackLoggingNoCompact=1','MallocStackLoggingDirectory='+str(logs)]
print(json.dumps({'nextLaunchOnly':True,'target':a.target,'command':command,'limits':'Opt-in allocation logging is NOT disk-bounded by this helper. Do not enable on reporter machine until a bounded collection procedure is validated.','noRestart':True,'status':'configuration preview; logging activation not proven'},indent=2))
if not a.enable_next_launch:raise SystemExit(0)
if logs.exists() and (logs.is_symlink() or logs.stat().st_uid!=0):raise SystemExit('Unsafe log directory')
logs.mkdir(mode=0o700,exist_ok=True);logs.chmod(0o700)
result=subprocess.run(command,capture_output=True,text=True,timeout=15)
if result.returncode:raise SystemExit('launchd rejected next-launch configuration; no security bypass attempted: '+result.stderr)
print('Next-launch override accepted by launchd. No restart performed. Actual allocator activation still requires local verification. Logs may contain sensitive stack/address metadata; keep local.')
