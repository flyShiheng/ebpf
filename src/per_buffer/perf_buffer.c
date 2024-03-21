#include "linux/bpf.h"
#include <bpf/libbpf.h>
#include <stdio.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sched.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <locale.h>
#include <poll.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>

#include <bpf/bpf.h>

static __u64 time_get_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000000000ull + ts.tv_nsec;
}

static __u64 start_time;
static __u64 cnt;

#define MAX_CNT 100000ll

static void print_bpf_output(void *ctx, int cpu, void *data, __u32 size) {
	printf("recv data_size: %d \n", size);
	printf("recv data     : %s \n", (char*)data);
}

int main() {
    struct bpf_link *link = NULL;
    struct bpf_program *bpf_prog = NULL;
    struct bpf_object  *obj = NULL;
	struct perf_buffer *pb = NULL;
    int ret;
    int map_fd;
	FILE *f;
    char* sec_name = "perf_buffer.bpf.o";
	struct perf_buffer_opts opts;

	obj = bpf_object__open_file(sec_name, NULL);
	if (libbpf_get_error(obj)) {
		printf("ERROR: opening BPF object file failed\n");
		return 1;
	}

	if (bpf_object__load(obj)) {
		printf("ERROR: loading BPF object file failed\n");
		goto err;
	}

	map_fd = bpf_object__find_map_fd_by_name(obj, "execve_count");
	if (map_fd < 0) {
		printf("ERROR: finding a map in obj file failed\n");
		goto err;
	}

	bpf_prog = bpf_object__find_program_by_name(obj, "sys_execve_perf_buffer");
	if (!bpf_prog) {
		printf("finding a prog in obj file failed\n");
		goto err;
	}

	link = bpf_program__attach(bpf_prog);
	if (libbpf_get_error(link)) {
		printf("ERROR: bpf_program__attach failed\n");
		link = NULL;
		goto err;
	}

	opts.sample_cb = print_bpf_output;
	opts.lost_cb = NULL;
	opts.ctx = NULL;
	pb = perf_buffer__new(map_fd, 8, &opts); // NULL, NULL, NULL
	ret = libbpf_get_error(pb);
	if (ret) {
		printf("failed to setup perf_buffer: %d\n", ret);
		return 1;
	}

	f = popen("taskset 1 dd if=/dev/zero of=/dev/null", "r");
	(void) f;

	start_time = time_get_ns();
	while ((ret = perf_buffer__poll(pb, 1000)) >= 0 && cnt < MAX_CNT) {
	}

err:
	bpf_link__destroy(link);
	bpf_object__close(obj);

    return 0;
}
