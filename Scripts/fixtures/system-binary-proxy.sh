#!/bin/sh
set -eu
# A harmless but structurally meaningful proxy-execution form: env clears the
# inherited environment before starting a shell command. The command itself is
# a no-op and performs no network or file activity.
# Keep the inert child alive long enough for recorder lineage sampling.
/usr/bin/env -i /bin/sh -c 'sleep 1'
