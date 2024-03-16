#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <sys/mman.h>

#define PAGE_SIZE 4096
#define BUFFER_SIZE 4096

int main() {
    int perf_fd, num_read;
    char buf[BUFFER_SIZE];

    perf_fd = open("/sys/kernel/debug/tracing/trace_pipe", O_RDONLY);
    if (perf_fd == -1) {
        printf("Failed to open perf event buffer\n");
        exit(EXIT_FAILURE);
    }

    while (1) {
        num_read = read(perf_fd, buf, BUFFER_SIZE);
        if (num_read == -1) {
            printf("Error reading from perf event buffer\n");
            return 0;
        }
        if (num_read == 0) {
            printf("No more data\n");
            break;
        }
        printf("%.*s", num_read, buf);
    }

    close(perf_fd);

    return 0;
}