#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include "test_map.h"
#include "test_map.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level >= LIBBPF_DEBUG)
		return 0;

	return vfprintf(stderr, format, args);
}

void handle_event(void *ctx, int cpu, void *data, unsigned int data_sz)
{
	struct data_t *m = data;

	printf("%-6d %-6d %-16s %-16s %s\n", m->pid, m->uid, m->command, m->path, m->message);
}

void lost_event(void *ctx, int cpu, long long unsigned int data_sz)
{
	printf("lost event\n");
}

int main()
{
    struct test_map_bpf *skel;
    int err;
	struct perf_buffer *pb = NULL;

	libbpf_set_print(libbpf_print_fn);

	skel = test_map_bpf__open_and_load();
	if (!skel) {
		printf("Failed to open BPF object\n");
		return 1;
	}

	err = test_map_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
		test_map_bpf__destroy(skel);
        return 1;
	}

    struct perf_buffer_opts opts;
    opts.sample_cb = handle_event;
    opts.lost_cb   = lost_event;

	pb = perf_buffer__new(bpf_map__fd(skel->maps.output), 8, &opts);
	if (!pb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		test_map_bpf__destroy(skel);
        return 1;
	}

	while (true) {
		err = perf_buffer__poll(pb, 100 /* timeout, ms */);
		// Ctrl-C gives -EINTR
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
	}

	perf_buffer__free(pb);
	test_map_bpf__destroy(skel);
	return -err;
}
