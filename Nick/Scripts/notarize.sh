#!/usr/bin/env bash
# notarize.sh — Archive, export (Developer ID), notarize, and staple Nick.app
#
# Usage:
#   ./Nick/Scripts/notarize.sh
#
# Optional overrides:
#   SCHEME            (default: Nick)
#   CONFIGURATION     (default: Release)
#   ARCHIVE_PATH      (default: build/Nick.xcarchive)
#   EXPORT_PATH       (default: build/export)
#   EXPORT_PLIST      (default: Nick/Scripts/ExportOptions.plist)
#   DMG_NAME          (default: Nick.dmg)
#   NOTARY_PROFILE    (default: NickNotary; created with notarytool store-credentials)
#
# MARK: - Nick
# Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
# Licensed under AGPL-3.0. See LICENSE for details.

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SCHEME="${SCHEME:-Nick}"
CONFIGURATION="${CONFIGURATION:-Release}"
ARCHIVE_PATH="${ARCHIVE_PATH:-build/Nick.xcarchive}"
EXPORT_PATH="${EXPORT_PATH:-build/export}"
EXPORT_PLIST="${EXPORT_PLIST:-Nick/Scripts/ExportOptions.plist}"
DMG_NAME="${DMG_NAME:-Nick.dmg}"
NOTARY_PROFILE="${NOTARY_PROFILE:-NickNotary}"

# ---------------------------------------------------------------------------
# Step 1 — Archive
# ---------------------------------------------------------------------------

echo "==> Step 1: Archiving ${SCHEME} (${CONFIGURATION})…"
xcodebuild archive \
  -project Nick.xcodeproj \
  -scheme   "${SCHEME}" \
  -configuration "${CONFIGURATION}" \
  -archivePath   "${ARCHIVE_PATH}" \
  CODE_SIGN_STYLE=Manual \
  | xcpretty 2>/dev/null || true

echo "  ✓ Archive created at ${ARCHIVE_PATH}"

# ---------------------------------------------------------------------------
# Step 2 — Export with Developer ID
# ---------------------------------------------------------------------------

echo "==> Step 2: Exporting archive…"
xcodebuild -exportArchive \
  -archivePath   "${ARCHIVE_PATH}" \
  -exportPath    "${EXPORT_PATH}" \
  -exportOptionsPlist "${EXPORT_PLIST}" \
  | xcpretty 2>/dev/null || true

APP_PATH="${EXPORT_PATH}/Nick.app"
echo "  ✓ Exported to ${APP_PATH}"

# ---------------------------------------------------------------------------
# Step 3 — Create DMG (optional — skip if create-dmg not installed)
# ---------------------------------------------------------------------------

DMG_PATH="${EXPORT_PATH}/${DMG_NAME}"
if command -v create-dmg &>/dev/null; then
  echo "==> Step 3: Creating DMG…"
  create-dmg \
    --volname "Nick" \
    --window-size 540 380 \
    --icon-size 128 \
    --icon Nick.app 160 190 \
    --app-drop-link 380 190 \
    "${DMG_PATH}" "${EXPORT_PATH}/"
  echo "  ✓ DMG created at ${DMG_PATH}"
else
  echo "  ⚠ create-dmg not found — skipping DMG creation. Submit the .app instead."
  DMG_PATH="${APP_PATH}"
fi

# ---------------------------------------------------------------------------
# Step 4 — Notarize
# ---------------------------------------------------------------------------

echo "==> Step 4: Submitting for notarization…"
xcrun notarytool submit "${DMG_PATH}" \
  --keychain-profile "${NOTARY_PROFILE}" \
  --wait \
  --output-format plist

echo "  ✓ Notarization complete."

# ---------------------------------------------------------------------------
# Step 5 — Staple
# ---------------------------------------------------------------------------

echo "==> Step 5: Stapling notarization ticket…"
xcrun stapler staple "${DMG_PATH}"
echo "  ✓ Stapled."

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------

echo ""
echo "=== Notarization pipeline finished ==="
echo "    Release artifact: ${DMG_PATH}"
