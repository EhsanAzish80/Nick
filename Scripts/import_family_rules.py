#!/usr/bin/env python3
# MARK: - Nick
# Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
# Licensed under AGPL-3.0. See LICENSE for details.
"""
Regenerates Rules/families/ from a YARA Forge release.

    python3 Scripts/import_family_rules.py 20260920

Selection criteria (all must hold):
  * the rule targets macOS / Mach-O or a cross-platform implant known on macOS;
  * it is not a hack-tool, RMM, exploit, "suspicious", or Windows/Linux-only rule;
  * its source repository's license permits redistribution (see ALLOWED);
  * it compiles standalone with the modules Nick's libyara ships (no pe/elf/dotnet/magic).

Rules with a family/malware name and YARA Forge quality >= 70 become
class = "signature" (HIGH); the rest become class = "behavior" (MEDIUM).
Run `python3 Scripts/rules_gate.py lint` and the `fp` gate afterwards.
Requires yara-python==4.5.4.
"""
import collections, io, json, os, re, sys, urllib.request, zipfile
import yara

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "Rules", "families")
ALLOWED = {
 'https://github.com/Neo23x0/signature-base':'DRL-1.1',
 'https://github.com/SEKOIA-IO/Community':'DRL-1.1',
 'https://github.com/ditekshen/detection':'BSD-2-Clause',
 'https://github.com/mandiant/red_team_tool_countermeasures/':'BSD-2-Clause',
 'https://github.com/chronicle/GCTI':'Apache-2.0',
 'https://github.com/volexity/threat-intel':'BSD-2-Clause',
 'https://github.com/advanced-threat-research/Yara-Rules/':'Apache-2.0',
 'https://github.com/eset/malware-ioc':'BSD-2-Clause',
 'https://github.com/WithSecureLabs/iocs':'BSD-2-Clause',
 'https://github.com/elceef/yara-rulz':'MIT',
 'https://github.com/craiu/yararules':'GPL-3.0',
 'https://github.com/cod3nym/detection-rules/':'DRL-1.1',
 'https://github.com/dr4k0nia/yara-rules':'DRL-1.1',
 'https://github.com/synacktiv/synacktiv-rules':'DRL-1.1',
}
MAC = re.compile(r'(?i)(\bmacos\b|macos_|_macos|\bosx\b|osx_|_osx|\bmac_|_mac_|_mac\b|mach-?o|0xfeedfac[ef]|0xcffaedfe|0xcafebab[ef]|0xbebafeca|atomic.?stealer|\bamos\b|_amos|banshee|cuckoo.?stealer|rustbucket|kandykorn|realst|cloudmensis|smooth.?operator|3cx.*mac|lockbit.*(mac|apple)|gimmick|triangulation|poseidon.?stealer|macsync|odyssey.?stealer|frigidstealer|shlayer|bundlore|pirrit|adload|xcsset|silver.?sparrow|jokerspy|toddlershark|rpcclient|beavertail|ferret)')
EXCLUDE = re.compile(r'(?i)(SUSP|HKTL|INDICATOR|RMM|EXPL|_TOOL_|TOOL_|Hacktool|PUA|_Win_|_Lin_|_Linux|Windows|_Win\b|WIN_|LNK|Maldoc|_Dotnet)')
EXCLUDE = re.compile(r'(?i)(SUSP|HKTL|INDICATOR|RMM|EXPL|_TOOL_|TOOL_|Hacktool|PUA|_Win_|_Lin_|_Linux|Windows|_Win\b|WIN_|LNK|Maldoc|_Dotnet)')
DROP={'TRELLIX_ARC_Chimera_Recordedtv_Modified','SIGNATURE_BASE_CN_Honker_MAC_IPMAC','SIGNATURE_BASE_Armitage_OSX','SEKOIA_Apt_Lazarus_Backdoored_Jslib'}
SIGWORDS=re.compile(r'(?i)(MAL|APT|Implant|Backdoor|Downloader|Dropper|RANSOM|MALWARE|Stealer|Keydnap|Thiefquest|Snaketurla|Evilosx|Bella|Rustbucket|Smoothoperator|Gimmick|Iconic)')
LICURL={'DRL-1.1':'https://github.com/SigmaHQ/Detection-Rule-License','BSD-2-Clause':'https://opensource.org/license/bsd-2-clause','Apache-2.0':'https://www.apache.org/licenses/LICENSE-2.0','MIT':'https://opensource.org/license/mit','GPL-3.0':'https://www.gnu.org/licenses/gpl-3.0.html'}
def split_rules(text):
    out=[]
    for block in re.split(r'\n(?=/\*\n \* YARA Rule Set)', text):
        r=re.search(r'Repository: (\S+)', block); repo=r.group(1) if r else None
        m=re.search(r' \* LICENSE\n \* \n(.*?)\n \*/', block, re.S); lictext=m.group(1) if m else ''
        for rule in re.split(r'\n(?=(?:private |global )*rule \w)', block):
            if re.match(r'(?:private |global )*rule \w', rule):
                out.append((rule.strip(), repo, lictext))
    return out


def download(tag, package):
    url = f"https://github.com/YARAHQ/yara-forge/releases/download/{tag}/yara-forge-rules-{package}.zip"
    with urllib.request.urlopen(url, timeout=120) as response:
        archive = zipfile.ZipFile(io.BytesIO(response.read()))
    name = next(n for n in archive.namelist() if n.endswith(".yar"))
    return archive.read(name).decode("utf-8", errors="replace")


def select(texts):
    seen, selected, licenses = set(), [], {}
    for text in texts:
        for rule, repo, lictext in split_rules(text):
            name = re.match(r'(?:private |global )*rule\s+(\w+)', rule).group(1)
            if name in seen or name in DROP or not MAC.search(rule):
                continue
            if rule.startswith(("private", "global")) or EXCLUDE.search(name) or repo not in ALLOWED:
                continue
            imports = [i for i in ["pe", "dotnet", "elf", "hash", "math", "macho", "magic", "cuckoo", "console", "string", "time"]
                       if re.search(r"\b" + i + r"\.", rule)]
            if any(i in ("magic", "cuckoo", "dotnet", "pe", "elf") for i in imports):
                continue
            try:
                yara.compile(source="".join(f'import "{i}"\n' for i in imports) + "\n" + rule)
            except yara.Error:
                continue
            seen.add(name)
            selected.append(dict(name=name, rule=rule, imports=imports, license=ALLOWED[repo], repo=repo))
            licenses[repo] = lictext
    return selected, licenses


def write(tag, selected, licenses):
    SIGWORDS = re.compile(r'(?i)(MAL|APT|Implant|Backdoor|Downloader|Dropper|RANSOM|MALWARE|Stealer|Keydnap|Thiefquest|Snaketurla|Evilosx|Bella|Rustbucket|Smoothoperator|Gimmick|Iconic)')
    LICURL = {'DRL-1.1': 'https://github.com/SigmaHQ/Detection-Rule-License', 'BSD-2-Clause': 'https://opensource.org/license/bsd-2-clause',
              'Apache-2.0': 'https://www.apache.org/licenses/LICENSE-2.0', 'MIT': 'https://opensource.org/license/mit',
              'GPL-3.0': 'https://www.gnu.org/licenses/gpl-3.0.html'}
    os.makedirs(os.path.join(OUT, "LICENSES"), exist_ok=True)
    groups = collections.defaultdict(list)
    for x in selected:
        rule = x["rule"]
        q = re.search(r"quality\s*=\s*(\d+)", rule)
        quality = int(q.group(1)) if q else 70
        cls = "signature" if (quality >= 70 and SIGWORDS.search(x["name"])) else "behavior"
        sev = "HIGH" if cls == "signature" else "MEDIUM"
        src = re.search(r'source_url\s*=\s*"([^"]+)"', rule)
        src = src.group(1) if src else x["repo"]
        rule = re.sub(r"\n\s*(severity|class|source|license)\s*=\s*[^\n]*", "", rule)
        rule = re.sub(r"(meta:\n)", lambda m: m.group(1) + f'\t\tclass = "{cls}"\n\t\tseverity = "{sev}"\n\t\tsource = "{src}"\n\t\tlicense = "{x["license"]}"\n', rule, count=1)
        vendor = re.sub(r"[^a-z0-9]+", "_", x["repo"].rstrip("/").split("/")[-2].lower())
        groups[(vendor, x["repo"], x["license"])].append((x["imports"], rule))
    for (vendor, repo, lic), items in sorted(groups.items()):
        imports = sorted({i for imp, _ in items for i in imp})
        head = (f"// Nick bundled family signatures — {repo}\n//\n"
                f"// Retrieved through YARA Forge release {tag} (https://github.com/YARAHQ/yara-forge)\n"
                f"// and selected by Scripts/import_family_rules.py.\n//\n"
                f"// License: {lic} ({LICURL[lic]}). Full text: Rules/families/LICENSES/{vendor}.txt\n"
                f"// Rule authorship and references are preserved in each rule's metadata.\n")
        body = "".join(f'import "{i}"\n' for i in imports) + ("\n" if imports else "") + "\n\n".join(r for _, r in items) + "\n"
        with open(os.path.join(OUT, f"{vendor}.yar"), "w") as fh:
            fh.write(head + "\n" + body)
        with open(os.path.join(OUT, "LICENSES", f"{vendor}.txt"), "w") as fh:
            fh.write(re.sub(r"^ \* ?", "", licenses[repo], flags=re.M).strip() + "\n")
    return {k[0]: len(v) for k, v in groups.items()}


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    tag = sys.argv[1]
    selected, licenses = select([download(tag, "core"), download(tag, "extended")])
    print(write(tag, selected, licenses))


if __name__ == "__main__":
    main()
