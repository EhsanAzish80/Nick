// Harmless, test-only backup workload. Built and launched by Xcode XCTest.
// Never reads outside its marked scratch directory; never opens the network.
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#include <stdatomic.h>
#include <errno.h>

enum { workers = 4, files = 512, passes = 16, phases = 3, bytes = 4096 };
static int rootfd;
static _Atomic unsigned long reads = 0, writes = 0, renames = 0, failures = 0;
static char payload[bytes];
static double seconds(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec / 1e9;
}
static void *worker(void *arg) {
    long id = (long)arg;
    char directory[32]; snprintf(directory, sizeof(directory), "worker-%ld", id);
    if (mkdirat(rootfd, directory, 0700) != 0) { atomic_fetch_add(&failures, 1); return NULL; }
    int dir = openat(rootfd, directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    if (dir < 0) { atomic_fetch_add(&failures, 1); return NULL; }
    for (int i = 0; i < files; i++) {
        char name[32]; snprintf(name, sizeof(name), "asset-%d.dat", i);
        int fd = openat(dir, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
        if (fd < 0 || write(fd, payload, bytes) != bytes) atomic_fetch_add(&failures, 1);
        if (fd >= 0) close(fd);
        atomic_fetch_add(&writes, 1);
    }
    char buffer[bytes];
    for (int phase = 0; phase < phases; phase++) {
        double start = seconds();
        for (int pass = 0; pass < passes; pass++) {
            for (int i = 0; i < files; i++) {
                char name[32]; snprintf(name, sizeof(name), "asset-%d.dat", i);
                struct stat st;
                if (fstatat(dir, name, &st, AT_SYMLINK_NOFOLLOW) != 0 || !S_ISREG(st.st_mode)) {
                    atomic_fetch_add(&failures, 1); continue;
                }
                int fd = openat(dir, name, O_RDONLY | O_NOFOLLOW);
                if (fd < 0 || read(fd, buffer, bytes) != bytes || memcmp(buffer, payload, bytes) != 0)
                    atomic_fetch_add(&failures, 1);
                if (fd >= 0) close(fd);
                atomic_fetch_add(&reads, 1);
                // Scan-only first phase; subsequent phases overlap small backup
                // staging writes/finalizations with the same file-open traffic.
                if (phase > 0 && i % 64 == 0) {
                    char temporary[40], final[40];
                    snprintf(temporary, sizeof(temporary), "stage-%d.dat.tmp", i);
                    snprintf(final, sizeof(final), "stage-%d.dat", i);
                    fd = openat(dir, temporary, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);
                    if (fd < 0 || write(fd, buffer, bytes) != bytes) atomic_fetch_add(&failures, 1);
                    if (fd >= 0) close(fd);
                    if (renameat(dir, temporary, dir, final) != 0) atomic_fetch_add(&failures, 1);
                    atomic_fetch_add(&writes, 1); atomic_fetch_add(&renames, 1);
                }
            }
        }
        fprintf(stderr, "fixture worker=%ld phase=%d seconds=%.3f\n", id, phase, seconds()-start);
    }
    close(dir); return NULL;
}
int main(int argc, char **argv) {
    if (argc != 3) return 64;
    char canonical[PATH_MAX];
    const char *prefix = "/private/tmp/NickBackupStress-";
    if (!realpath(argv[1], canonical) || strncmp(canonical, prefix, strlen(prefix)) != 0) return 65;
    struct stat st;
    if (lstat(argv[1], &st) || !S_ISDIR(st.st_mode) || S_ISLNK(st.st_mode)) return 65;
    rootfd = open(canonical, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    if (rootfd < 0) return 65;
    int marker = openat(rootfd, ".nick-backup-stress-fixture", O_RDONLY | O_NOFOLLOW);
    char nonce[128] = {0};
    ssize_t count = marker < 0 ? -1 : read(marker, nonce, sizeof(nonce)-1);
    if (marker >= 0) close(marker);
    if (count <= 0 || strcmp(nonce, argv[2]) != 0) return 65;
    memset(payload, 'A', bytes);
    memcpy(payload, "Harmless Nick synthetic backup fixture\n", 38);
    double start = seconds();
    pthread_t threads[workers];
    for (long i = 0; i < workers; i++) {
        if (pthread_create(&threads[i], NULL, worker, (void *)i) != 0) return 70;
    }
    for (int i = 0; i < workers; i++) pthread_join(threads[i], NULL);
    close(rootfd);
    printf("{\"workers\":%d,\"files\":%d,\"reads\":%lu,\"writes\":%lu,\"renames\":%lu,\"failures\":%lu,\"seconds\":%.6f}\n",
        workers, workers*files, reads, writes, renames, failures, seconds()-start);
    return failures == 0 ? 0 : 1;
}
