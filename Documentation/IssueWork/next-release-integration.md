# Nick 5.1.7 release integration

Integration branch: `fix/release-5.1.7`.

Each issue keeps its own `fix/issue-*` branch and draft pull request. Add an issue's implementation here only after its focused tests and review pass. This branch is not a release approval, and does not update the appcast or website.

## Priority

1. #139 / #141 — app activation and UI stalls. Establish the blocking path; do not attribute the stall to an alert without evidence.
2. #129 / #142 — WhatsApp blocked from its own cookies. Preserve cross-application credential enforcement.
3. #122 / #152 — remaining backup termination evidence. Implement only demonstrated gaps; preserve the completed performance fixes.
4. #128 / #143 — Time Machine copies of canaries.
5. #138 / #150 and #140 / #151 — simulator GeoServices and XCTest SpringBoard, independently tested and reviewed.
6. #130 / #144, #131 / #145, #132 / #146, #133 / #147 — updater, FileProvider, MobileAsset and CloudDocs rename cases; each remains separate.
7. #134 / #148 — temporary-output shell classification.
8. #137 / #149 — SSH workflow observation noise.
9. #51 / #153 — Performance Diagnostics main-thread warning.
10. #49 / #154 — delivered notification count refresh.

## Completion gate for each issue

- Document the confirmed cause and narrowly scoped behavior change in its issue plan.
- Add meaningful positive and negative regression coverage where applicable.
- Run local tests through Xcode and record actual results; do not count draft/planning CI as validation.
- Commit and push only that issue's files; preserve unrelated diagnostic work.
- Update its PR checklist honestly, then integrate the verified commit(s) here.
- Keep unresolved claims explicit. No blanket process, signing, directory or extension exemptions.

## Current state

No issue implementation has been integrated. All issue PRs are draft work plans. Public release, appcast and website changes require a later instruction.
