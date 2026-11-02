#include <fcntl.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 2) return 64;
    int descriptor = open(argv[1], O_RDONLY);
    if (descriptor < 0) return 65;
    char byte = 0;
    ssize_t result = read(descriptor, &byte, sizeof(byte));
    close(descriptor);
    return result < 0 ? 66 : 0;
}
