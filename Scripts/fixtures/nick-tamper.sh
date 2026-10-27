#!/bin/sh
set -eu
pid=$(pgrep -x com.ehsanazish.nick.NickExtension | head -n 1 || true)
if [ -z "$pid" ]; then echo "Nick endpoint extension is not running"; exit 1; fi
kill -STOP "$pid" 2>/dev/null || true
sleep 1
