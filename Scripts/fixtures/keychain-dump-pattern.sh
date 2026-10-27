#!/bin/sh
set -eu
/usr/bin/security find-generic-password -s com.3nsofts.nick.missing-scorecard-item -w >/dev/null 2>&1 || true
