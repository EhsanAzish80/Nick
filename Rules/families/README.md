# Family signatures

Third-party YARA rules for specific macOS malware families and cross-platform
implants. They carry `class = "signature"` (or `"behavior"` for lower-quality
rules), so Nick reports a match as a threat in every location.

- **Source:** [YARA Forge](https://github.com/YARAHQ/yara-forge) release packages
  (core + extended), which aggregate vetted public repositories.
- **Selection:** `Scripts/import_family_rules.py` keeps macOS / Mach-O and
  cross-platform implant rules whose source repository license permits
  redistribution (DRL 1.1, BSD-2-Clause, Apache-2.0, MIT, GPL-3.0). Hack tools,
  RMM software, exploits, and "suspicious"-only rules are excluded.
- **Licenses:** one text per source in `LICENSES/`. Rule `author`, `reference`,
  `source`, and `license` metadata are preserved, and Nick shows the rule author
  with every match, as the Detection Rule License requires.

## Updating

```sh
python3 -m pip install "yara-python==4.5.4"
python3 Scripts/import_family_rules.py <yara-forge-release-tag>
python3 Scripts/rules_gate.py lint
python3 Scripts/rules_gate.py fp          # on a clean Mac; CI runs it too
```

Review the diff before committing. A `signature` rule that matches anything in
the benign corpus must be fixed, demoted to `behavior`, or dropped.
