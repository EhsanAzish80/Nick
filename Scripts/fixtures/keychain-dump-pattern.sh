#!/bin/sh
set -eu
root="${NICK_FIXTURE_ROOT:?}"
keychain="$root/Library/Keychains/nick-scorecard.keychain"
copied="$root/copied.keychain-db"
password='nick-scorecard-only'
umask 077
mkdir -p "$(dirname "$keychain")"
trap 'security delete-keychain "$keychain" >/dev/null 2>&1 || true; rm -f "$copied"' EXIT
security create-keychain -p "$password" "$keychain"
if [ -f "$keychain-db" ]; then
    keychain="$keychain-db"
elif [ ! -f "$keychain" ]; then
    printf '%s\n' 'The synthetic Keychain file was not created.' >&2
    exit 1
fi
printf '%s\n' 'Unlocking the synthetic Keychain'
security unlock-keychain -p "$password" "$keychain"
printf '%s\n' 'Adding the synthetic item'
security add-generic-password -a nick-scorecard -s 'Chrome Safe Storage' -w synthetic-only -T /usr/bin/security "$keychain"
printf '%s\n' 'Reading the synthetic item'
security find-generic-password -a nick-scorecard -s 'Chrome Safe Storage' -w "$keychain" >/dev/null
printf '%s\n' 'Copying the synthetic Keychain'
cp "$keychain" "$copied"
sleep 1
