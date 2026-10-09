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

# Keep backticked repository paths in the public external-review handoff
# anchored to the live tree. Prose tokens and external fixture paths are not
# selected; additions under the repository roots below are checked automatically.
review_scope="Documentation/EXTERNAL_SECURITY_REVIEW_SCOPE.md"
if [[ ! -s "$review_scope" ]]; then
  echo "External security review scope is missing or empty: $review_scope" >&2
  exit 1
fi

while IFS= read -r path; do
  path="${path%/}"
  if [[ ! -e "$path" ]]; then
    echo "External security review path is missing: $path" >&2
    exit 1
  fi
done < <(ruby -e '
  File.read(ARGV.fetch(0)).scan(/`([^`]+)`/).flatten.each do |token|
    puts token if token.match?(%r{\A(?:\.github/|Nick/|NickExtension/|NickNetFilter/|NickUninstaller/|Packaging/|Rules/|Shared/|SECURITY\.md\z)})
  end
' "$review_scope")

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
