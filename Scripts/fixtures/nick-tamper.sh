#!/bin/sh
set -eu
[ "$(/usr/bin/id -u)" -eq 0 ] || { echo "The Endpoint Security fixture requires root"; exit 1; }
pid=$(/bin/ps -axo pid=,uid=,comm= | /usr/bin/awk '
    $2 == 0 && $3 ~ /^\/Library\/SystemExtensions\// &&
    $3 ~ /\/com\.ehsanazish\.nick\.NickExtension\.systemextension\/Contents\/MacOS\/com\.ehsanazish\.nick\.NickExtension$/ {
        count++; pid = $1
    }
    END { if (count == 1) print pid }
')
[ -n "$pid" ] || { echo "Expected one running Nick Endpoint Security extension"; exit 1; }
work=$(/usr/bin/mktemp -d /private/tmp/nick-signal-fixture.XXXXXX)
trap 'rm -rf "$work"' EXIT
cat > "$work/signal.c" <<'C'
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    pid_t pid = (pid_t)strtol(argv[1], NULL, 10);
    if (pid <= 1) return 2;
    if (kill(pid, SIGSTOP) != 0) {
        perror("SIGSTOP");
        return 1;
    }
    if (kill(pid, SIGCONT) != 0) {
        perror("SIGCONT");
        return 1;
    }
    puts("SIGSTOP succeeded and the extension was resumed");
    return 0;
}
C
/usr/bin/clang -Wall -Wextra -o "$work/signal" "$work/signal.c"
# The platform sender resumes the extension even if the fixture is interrupted.
(/bin/sleep 1; /bin/kill -CONT "$pid" 2>/dev/null || true) &
watchdog=$!
status=0
"$work/signal" "$pid" || status=$?
wait "$watchdog"
exit "$status"
