// Harmless, test-only backup workload. Built and launched by Xcode XCTest.
// Operates only inside an owner-only, nonce-marked scratch directory.
// Never opens the network or reads files outside that directory descriptor.
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdatomic.h>

enum { workers = 4 };
enum { files = 512 };
enum { passes = 16 };
enum { phases = 3 };
enum { bytes = 4096 };
static int rootfd;
static _Atomic unsigned long reads = 0;
static _Atomic unsigned long writes = 0;
static _Atomic unsigned long renames = 0;
static _Atomic unsigned long failures = 0;
static char payload[bytes];

static double seconds(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec / 1e9;
}

static void create_asset(int dir, int index) {
    char name[32];
    snprintf(name, sizeof(name), "asset-%d.dat", index);
    int fd = openat(dir, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0 || write(fd, payload, bytes) != bytes) atomic_fetch_add(&failures, 1);
    if (fd >= 0) close(fd);
    atomic_fetch_add(&writes, 1);
}

static int read_asset(int dir, int index, char *buffer) {
    char name[32];
    snprintf(name, sizeof(name), "asset-%d.dat", index);
    struct stat st;
    if (fstatat(dir, name, &st, AT_SYMLINK_NOFOLLOW) != 0 || !S_ISREG(st.st_mode)) {
        atomic_fetch_add(&failures, 1);
        return 0;
    }
    int fd = openat(dir, name, O_RDONLY | O_NOFOLLOW);
    if (fd < 0 || read(fd, buffer, bytes) != bytes || memcmp(buffer, payload, bytes) != 0)
        atomic_fetch_add(&failures, 1);
    if (fd >= 0) close(fd);
    atomic_fetch_add(&reads, 1);
    return 1;
}

static void stage_asset(int dir, int index, const char *buffer) {
    char temporary[40];
    char final[40];
    snprintf(temporary, sizeof(temporary), "stage-%d.dat.tmp", index);
    snprintf(final, sizeof(final), "stage-%d.dat", index);
    int fd = openat(dir, temporary, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);
    if (fd < 0 || write(fd, buffer, bytes) != bytes) atomic_fetch_add(&failures, 1);
    if (fd >= 0) close(fd);
    if (renameat(dir, temporary, dir, final) != 0) atomic_fetch_add(&failures, 1);
    atomic_fetch_add(&writes, 1);
    atomic_fetch_add(&renames, 1);
}

static void run_phase(int dir, long id, int phase) {
    char buffer[bytes];
    double start = seconds();
    for (int pass = 0; pass < passes; pass++) {
        for (int index = 0; index < files; index++) {
            if (!read_asset(dir, index, buffer)) continue;
            // Scan-only first; later phases add backup staging/finalization.
            if (phase > 0 && index % 64 == 0) stage_asset(dir, index, buffer);
        }
    }
    fprintf(stderr, "fixture worker=%ld phase=%d seconds=%.3f\n", id, phase, seconds()-start);
}

static void *worker(void *arg) {
    long id = (long)arg;
    char directory[32];
    snprintf(directory, sizeof(directory), "worker-%ld", id);
    if (mkdirat(rootfd, directory, 0700) != 0) {
        atomic_fetch_add(&failures, 1);
        return NULL;
    }
    int dir = openat(rootfd, directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    if (dir < 0) {
        atomic_fetch_add(&failures, 1);
        return NULL;
    }
    for (int index = 0; index < files; index++) create_asset(dir, index);
    for (int phase = 0; phase < phases; phase++) run_phase(dir, id, phase);
    close(dir);
    return NULL;
}

static int open_fixture_root(const char *path, const char *expected_nonce) {
    const char *name = strrchr(path, '/');
    name = name ? name + 1 : path;
    const char *prefix = "NickBackupStress-";
    if (strncmp(name, prefix, strlen(prefix)) != 0) return -1;
    int dir = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    if (dir < 0) return -1;
    struct stat st;
    // Validate the opened descriptor, not a pathname that can race a rename.
    if (fstat(dir, &st) != 0 || st.st_uid != geteuid() || (st.st_mode & 077) != 0) {
        close(dir);
        return -1;
    }
    int marker = openat(dir, ".nick-backup-stress-fixture", O_RDONLY | O_NOFOLLOW);
    char nonce[128] = {0};
    ssize_t count = marker < 0 ? -1 : read(marker, nonce, sizeof(nonce)-1);
    if (marker >= 0) close(marker);
    if (count <= 0 || strcmp(nonce, expected_nonce) != 0) {
        close(dir);
        return -1;
    }
    return dir;
}

int main(int argc, char **argv) {
    if (argc != 3) return 64;
    rootfd = open_fixture_root(argv[1], argv[2]);
    if (rootfd < 0) return 65;
    memset(payload, 'A', bytes);
    memcpy(payload, "Harmless Nick synthetic backup fixture\n", 38);
    double start = seconds();
    pthread_t threads[workers];
    for (long index = 0; index < workers; index++) {
        if (pthread_create(&threads[index], NULL, worker, (void *)index) != 0) return 70;
    }
    for (int index = 0; index < workers; index++) pthread_join(threads[index], NULL);
    close(rootfd);
    printf("{\"workers\":%d,\"files\":%d,\"reads\":%lu,\"writes\":%lu,\"renames\":%lu,\"failures\":%lu,\"seconds\":%.6f}\n",
        workers, workers*files, reads, writes, renames, failures, seconds()-start);
    return failures == 0 ? 0 : 1;
}
