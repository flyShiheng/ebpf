#include "linux/bpf.h"
#include <linux/if_link.h>
#include <linux/limits.h>
#include <net/if.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <libgen.h>

// #include "bpf/libbpf.h"
// #include <bpf/bpf.h>

static __u32 xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;

// static int do_attach(int idx, int prog_fd, const char *name)
// {
// 	int err;

// 	err = bpf_xdp_attach(idx, prog_fd, xdp_flags, NULL);
// 	if (err < 0) {
// 		printf("ERROR: failed to attach program to %s\n", name);
// 	}

// 	return err;
// }

// static int do_detach(int ifindex, const char *ifname, const char *app_name)
// {
// 	LIBBPF_OPTS(bpf_xdp_attach_opts, opts);
// 	struct bpf_prog_info prog_info = {};
// 	char prog_name[BPF_OBJ_NAME_LEN];
// 	__u32 info_len, curr_prog_id;
// 	int prog_fd;
// 	int err = 1;

// 	if (bpf_xdp_query_id(ifindex, xdp_flags, &curr_prog_id)) {
// 		printf("ERROR: bpf_xdp_query_id failed (%s)\n",
// 		       strerror(errno));
// 		return err;
// 	}

// 	if (!curr_prog_id) {
// 		printf("ERROR: flags(0x%x) xdp prog is not attached to %s\n",
// 		       xdp_flags, ifname);
// 		return err;
// 	}

// 	info_len = sizeof(prog_info);
// 	prog_fd = bpf_prog_get_fd_by_id(curr_prog_id);
// 	if (prog_fd < 0) {
// 		printf("ERROR: bpf_prog_get_fd_by_id failed (%s)\n",
// 		       strerror(errno));
// 		return prog_fd;
// 	}

// 	err = bpf_prog_get_info_by_fd(prog_fd, &prog_info, &info_len);
// 	if (err) {
// 		printf("ERROR: bpf_prog_get_info_by_fd failed (%s)\n",
// 		       strerror(errno));
// 		goto close_out;
// 	}
// 	snprintf(prog_name, sizeof(prog_name), "%s_prog", app_name);
// 	prog_name[BPF_OBJ_NAME_LEN - 1] = '\0';

// 	if (strcmp(prog_info.name, prog_name)) {
// 		printf("ERROR: %s isn't attached to %s\n", app_name, ifname);
// 		err = 1;
// 		goto close_out;
// 	}

// 	opts.old_prog_fd = prog_fd;
// 	err = bpf_xdp_detach(ifindex, xdp_flags, &opts);
// 	if (err < 0)
// 		printf("ERROR: failed to detach program from %s (%s)\n",
// 		       ifname, strerror(errno));
// close_out:
// 	close(prog_fd);
// 	return err;
// }

int main(int argc, char **argv) {
	const char *prog_name = "xdp_perf_buffer";
    char* sec_name = "perf_buffer.bpf.o";
	char* tarce_log = "/sys/kernel/debug/tracing/trace_pipe";
	struct bpf_program *prog = NULL;
	struct bpf_program *pos;
	int prog_fd = -1, map_fd = -1;
	struct bpf_object *obj;
	int opt, i, idx, err;
	int attach = 1;
	int ret = 0;
	char line_buff[4096] = {0};

	while ((opt = getopt(argc, argv, ":d")) != -1) {
		switch (opt) {
		case 'd':
			attach = 0;
			break;
		default:
			return 1;
		}
	}

	if (attach) {
		obj = bpf_object__open_file(sec_name, NULL);
		if (libbpf_get_error(obj))
			return 1;

		prog = bpf_object__next_program(obj, NULL);
		bpf_program__set_type(prog, BPF_PROG_TYPE_XDP);

		err = bpf_object__load(obj);
		if (err) {
			printf("Does kernel support devmap lookup?\n");
			return 1;
		}

		bpf_object__for_each_program(pos, obj) {
			sec_name = bpf_program__section_name(pos);
			if (sec_name && !strcmp(sec_name, prog_name)) {
				prog = pos;
				break;
			}
		}
		prog_fd = bpf_program__fd(prog);
		if (prog_fd < 0) {
			printf("program not found: %s\n", strerror(prog_fd));
			return 1;
		}
	}

	for (i = optind; i < argc; ++i) {
		idx = if_nametoindex(argv[i]);
		if (!idx)
			idx = strtoul(argv[i], NULL, 0);

		if (!idx) {
			fprintf(stderr, "Invalid arg\n");
			return 1;
		}
		printf("idx:%d, attach:%d, argv[%d]:%s\n", idx, attach, i, argv[i]);
		// if (!attach) {
		// 	ret = do_detach(idx, argv[i], prog_name);
		// } else {
		// 	ret = do_attach(idx, prog_fd, argv[i]);
		// }
	}

	// int trace_fd = open(tarce_log, O_RDONLY);
    // if (trace_fd < 0) {
    //     goto err;
    // }

    // while (true) {
    //     if(read(trace_fd, line_buff, sizeof(line_buff))) {
    //        printf("get trace: %s\n", line_buff);
    //        break;
    //     } else {
    //         printf("Waiting for a sys_clone event\n");
    //         sleep(1);
    //     }
    // }

err:
	bpf_object__close(obj);

    return 0;
}
