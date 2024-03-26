#include "linux/bpf.h"
#include "src/libbpf.h"
#include "src/libbpf_common.h"
#include "linux/if_link.h"
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

static __u32 xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;

static int do_attach(int idx, int prog_fd, const char *name)
{
	int err = bpf_xdp_attach(idx, prog_fd, xdp_flags, NULL);
	if (err < 0) {
		printf("ERROR: failed to attach program to %s\n", name);
	}
	return err;
}

static int do_detach(int ifindex, const char *ifname, const char *app_name)
{
	LIBBPF_OPTS(bpf_xdp_attach_opts, opts);
	struct bpf_prog_info prog_info = {};
	char prog_name[BPF_OBJ_NAME_LEN];
	__u32 info_len, curr_prog_id;
	int prog_fd;
	int err = 1;

	if (bpf_xdp_query_id(ifindex, xdp_flags, &curr_prog_id)) {
		printf("ERROR: bpf_xdp_query_id failed (%s)\n",
		       strerror(errno));
		return err;
	}

	if (!curr_prog_id) {
		printf("ERROR: flags(0x%x) xdp prog is not attached to %s\n",
		       xdp_flags, ifname);
		return err;
	}

	info_len = sizeof(prog_info);
	prog_fd = bpf_prog_get_fd_by_id(curr_prog_id);
	if (prog_fd < 0) {
		printf("ERROR: bpf_prog_get_fd_by_id failed (%s)\n",
		       strerror(errno));
		return prog_fd;
	}

	err = bpf_prog_get_info_by_fd(prog_fd, &prog_info, &info_len);
	if (err) {
		printf("ERROR: bpf_prog_get_info_by_fd failed (%s)\n",
		       strerror(errno));
		goto close_out;
	}
	snprintf(prog_name, sizeof(prog_name), "%s_prog", app_name);
	prog_name[BPF_OBJ_NAME_LEN - 1] = '\0';

	if (strcmp(prog_info.name, prog_name)) {
		printf("ERROR: %s isn't attached to %s\n", app_name, ifname);
		err = 1;
		goto close_out;
	}

	opts.old_prog_fd = prog_fd;
	err = bpf_xdp_detach(ifindex, xdp_flags, &opts);
	if (err < 0)
		printf("ERROR: failed to detach program from %s (%s)\n",
		       ifname, strerror(errno));
	/* TODO: Remember to cleanup map, when adding use of shared map
	 *  bpf_map_delete_elem((map_fd, &idx);
	 */
close_out:
	close(prog_fd);
	return err;
}

int main(int argc, char **argv) {
    struct bpf_program *bpf_prog = NULL;
    struct bpf_object *obj = NULL;
    char* sec_name = "xdp.bpf.c.o";
    char* tarce_log = "/sys/kernel/debug/tracing/trace_pipe";
	const char *prog_name = "xdp_perf_buffer";
    char line_buff[4096] = {0};
	int attach = 1, opt, prog_fd = -1, i, idx, ret;
	char* net_name = NULL;

	if (argc < 2) {
		printf("parameter num is less 2\n");
		return 0;
	}

	attach = (strcmp(argv[1], "attach") == 0) ? 1 : 0;
	if (argc == 3) {
		net_name = argv[i];
	}

	if (attach == 1) {
		obj = bpf_object__open_file(sec_name, NULL);
		if (libbpf_get_error(obj)) {
			printf("ERROR: opening BPF object file failed\n");
			return 1;
		}

		bpf_prog = bpf_object__find_program_by_name(obj, "xdp_perf_buffer");
		if (!bpf_prog) {
			printf("finding a prog in obj file failed\n");
			goto err;
		}
		bpf_program__set_type(bpf_prog, BPF_PROG_TYPE_XDP);
		
		if (bpf_object__load(obj)) {
			printf("ERROR: loading BPF object file failed\n");
			goto err;
		}
	
		prog_fd = bpf_program__fd(bpf_prog);
	}

	idx = if_nametoindex(net_name);
	printf("net_name: %s, idx:%d\n", net_name, idx);
	if (!idx)
		idx = strtoul(net_name, NULL, 0);

	if (!idx) {
		printf("Invalid arg\n");
		return 1;
	}
	if (!attach) {
		ret = do_detach(idx, net_name, prog_name);
	} else {
		ret = do_attach(idx, prog_fd, prog_name);
	}

err:
	bpf_object__close(obj);

    return 0;
}
