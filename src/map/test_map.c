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
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

int main() {
    struct bpf_link *link = NULL;
    struct bpf_program *bpf_prog = NULL;
    struct bpf_object *obj = NULL;
    int key, next_key;
    __u64 value;
    int map_fd;
    char* sec_name = "test_map.bpf.o";

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

	bpf_prog = bpf_object__find_program_by_name(obj, "kprobe_bpf_geteuid");
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

    sleep(3);
	while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
		bpf_map_lookup_elem(map_fd, &next_key, &value);
		key = next_key;
        printf("key:%d, value:%llu\n", key, value);
    }

err:
	bpf_link__destroy(link);
	bpf_object__close(obj);

    return 0;
}
