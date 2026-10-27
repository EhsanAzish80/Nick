#!/bin/sh
set -eu
/usr/bin/sw_vers >/dev/null
/usr/sbin/system_profiler SPSoftwareDataType >/dev/null
