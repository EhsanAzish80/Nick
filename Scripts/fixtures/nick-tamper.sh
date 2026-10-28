#!/bin/sh
set -eu
/usr/bin/systemextensionsctl uninstall UXGW5V3BY6 com.ehsanazish.nick.NickNetFilter 2>/dev/null || true
pid=$(/usr/bin/pgrep -x Nick | /usr/bin/head -n 1 || true)
if [ -z "$pid" ]; then echo "Nick app is not running"; exit 1; fi
/bin/kill -9 "$pid"
sleep 2
/usr/bin/open -a /Applications/Nick.app
sleep 3
