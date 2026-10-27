#!/bin/sh
set -eu
/bin/ps -axo pid,ppid,comm >/dev/null
