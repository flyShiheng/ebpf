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
    char* sec_name = "hello_world.bpf.o";
    char* tarce_log = "/sys/kernel/debug/tracing/trace_pipe";
    char line_buff[4096] = {0};

	obj = bpf_object__open_file(sec_name, NULL);
	if (libbpf_get_error(obj)) {
		printf("ERROR: opening BPF object file failed\n");
		return 1;
	}

	bpf_prog = bpf_object__find_program_by_name(obj, "sys_execve_hello");
	if (!bpf_prog) {
		printf("finding a prog in obj file failed\n");
		goto err;
	}

	if (bpf_object__load(obj)) {
		printf("ERROR: loading BPF object file failed\n");
		goto err;
	}

	link = bpf_program__attach(bpf_prog);
	if (libbpf_get_error(link)) {
		printf("ERROR: bpf_program__attach failed\n");
		link = NULL;
		goto err;
	}

	int trace_fd = open(tarce_log, O_RDONLY);
    if (trace_fd < 0) {
        goto err;
    }

    while (true) {
        if(read(trace_fd, line_buff, sizeof(line_buff))) {
           printf("get trace: %s\n", line_buff);
           break;
        } else {
            printf("Waiting for a sys_clone event\n");
            sleep(1);
        }
    }

err:
	bpf_link__destroy(link);
	bpf_object__close(obj);

    return 0;
}
