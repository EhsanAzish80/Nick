#!/bin/sh
set -eu
# A harmless but structurally meaningful proxy-execution form: env clears the
# inherited environment before starting a shell command. The command itself is
# a no-op and performs no network or file activity.
/usr/bin/env -i /bin/sh -c ':'
