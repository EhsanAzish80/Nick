#!/usr/bin/env bash

set -euo pipefail

required_files=(
  ARCHITECTURE.md
  CHANGELOG.md
  CITATION.cff
  CODE_OF_CONDUCT.md
  CONTRIBUTING.md
  LICENSE
  README.md
  SECURITY.md
  SUPPORT.md
  codecov.yml
)

for file in "${required_files[@]}"; do
  if [[ ! -s "$file" ]]; then
    echo "Required repository file is missing or empty: $file" >&2
    exit 1
  fi
done

while IFS= read -r file; do
  case "$file" in
    *.p12|*.p8|*.mobileprovision|*.provisionprofile|*.pkg|*.dmg|*.xcresult/*)
      echo "Sensitive or generated artifact must not be tracked: $file" >&2
      exit 1
      ;;
  esac
done < <(git ls-files)

while IFS= read -r -d '' file; do
  plutil -lint "$file"
done < <(git ls-files -z '*.plist' '*.xcprivacy')

ruby -e '
  require "yaml"
  ARGV.each { |path| YAML.parse_file(path) }
' CITATION.cff codecov.yml .github/dependabot.yml .github/release.yml \
  .github/workflows/*.yml \
  .github/ISSUE_TEMPLATE/*.yml

echo "Repository metadata validation passed."
