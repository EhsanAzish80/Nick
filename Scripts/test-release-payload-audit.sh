#!/bin/zsh

set -euo pipefail

export COPYFILE_DISABLE=1

SCRIPT_DIR=${0:A:h}
PROJECT_DIR=${SCRIPT_DIR:h}
AUDITOR="${PROJECT_DIR}/Packaging/audit-package-payload.sh"
STAGER="${PROJECT_DIR}/Packaging/stage-package-root.sh"
PACKAGE_BUILDER="${PROJECT_DIR}/Packaging/build-clean-component-package.sh"
TEST_DIR=$(mktemp -d /private/tmp/NickPayloadAuditTests.XXXXXX)
trap 'rm -rf "${TEST_DIR}"' EXIT

make_fixture() {
  local fixture_name=$1
  local include_appledouble=$2
  local fixture_dir="${TEST_DIR}/${fixture_name}"
  local root_dir="${fixture_dir}/root"

  mkdir -p "${root_dir}/Applications/Test.app/Contents/MacOS"
  print 'test executable' > "${root_dir}/Applications/Test.app/Contents/MacOS/Test"
  if [[ "${include_appledouble}" == "yes" ]]; then
    print 'metadata' > "${root_dir}/Applications/Test.app/Contents/MacOS/._Test"
  fi

  (
    cd "${root_dir}"
    COPYFILE_DISABLE=1 bsdtar --no-xattrs --format cpio -cf \
      "${fixture_dir}/Payload.cpio" .
  )
  gzip -9 "${fixture_dir}/Payload.cpio"
  mv "${fixture_dir}/Payload.cpio.gz" "${fixture_dir}/Payload"
  : > "${fixture_dir}/Bom"
  print '<pkg-info/>' > "${fixture_dir}/PackageInfo"
  (
    cd "${fixture_dir}"
    xar -cf "${TEST_DIR}/${fixture_name}.pkg" Bom PackageInfo Payload
  )
}

make_fixture clean no
make_fixture dirty yes

# Exercise the same clean staging entry point as release.sh. The source tree
# deliberately carries extended attributes; the resulting package must contain
# no serialized AppleDouble entries.
xattr_source="${TEST_DIR}/xattr-source/Nick.app"
mkdir -p "${xattr_source}/Contents/MacOS" \
  "${xattr_source}/Contents/Applications/Nick Uninstaller.app/Contents/MacOS"
print 'nick executable' > "${xattr_source}/Contents/MacOS/Nick"
print 'uninstaller executable' > \
  "${xattr_source}/Contents/Applications/Nick Uninstaller.app/Contents/MacOS/Nick Uninstaller"
xattr -w com.ehsanazish.nick.test-metadata 'release-pipeline-test' \
  "${xattr_source}/Contents/MacOS/Nick"
[[ -n "$(xattr "${xattr_source}/Contents/MacOS/Nick")" ]] || {
  print -u2 "The xattr staging fixture did not contain an extended attribute."
  exit 1
}

xattr_root="${TEST_DIR}/xattr-staged-root"
"${STAGER}" "${xattr_source}" "${xattr_root}"
if xattr -lr "${xattr_root}" | grep -q \
  'com.ehsanazish.nick.test-metadata'; then
  print -u2 "Clean staging retained the source test extended attribute."
  exit 1
fi

"${PACKAGE_BUILDER}" \
  "${xattr_root}" \
  com.ehsanazish.nick.payload-audit-test \
  1 \
  '' \
  "${TEST_DIR}/xattr-staged.pkg"
xattr_output=$("${AUDITOR}" "${TEST_DIR}/xattr-staged.pkg")
[[ "${xattr_output}" == *"AppleDouble entries: 0"* ]] || {
  print -u2 "The xattr-bearing staging fixture produced AppleDouble entries."
  exit 1
}

clean_output=$("${AUDITOR}" "${TEST_DIR}/clean.pkg")
[[ "${clean_output}" == *"AppleDouble entries: 0"* ]] || {
  print -u2 "Clean package was not accepted."
  exit 1
}

if dirty_output=$("${AUDITOR}" "${TEST_DIR}/dirty.pkg" 2>&1); then
  print -u2 "Dirty package was accepted."
  exit 1
fi
[[ "${dirty_output}" == *"AppleDouble entries: 1"* ]] || {
  print -u2 "Dirty package count was not reported."
  exit 1
}
[[ "${dirty_output}" == *"Contents/MacOS/._Test"* ]] || {
  print -u2 "Dirty package path was not reported."
  exit 1
}

print "Release payload audit tests passed."
