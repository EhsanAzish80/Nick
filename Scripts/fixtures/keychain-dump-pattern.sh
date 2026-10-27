#!/bin/sh
set -eu
root="${NICK_FIXTURE_ROOT:?}"
keychain="$root/nick-scorecard.keychain-db"
copied="$root/copied.keychain-db"
password='nick-scorecard-only'
trap 'security delete-keychain "$keychain" >/dev/null 2>&1 || true; rm -f "$copied"' EXIT
security create-keychain -p "$password" "$keychain"
security add-generic-password -a nick-scorecard -s 'Chrome Safe Storage' -w synthetic-only -T /usr/bin/security "$keychain"
security unlock-keychain -p "$password" "$keychain"
security find-generic-password -a nick-scorecard -s 'Chrome Safe Storage' -w "$keychain" >/dev/null
cp "$keychain" "$copied"
sleep 1
