
#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, int);
	__type(value, long);
	__uint(max_entries, 100);
} execve_count SEC(".maps");

SEC("kprobe/__x64_sys_execve")
int kprobe_bpf_geteuid(struct pt_regs *ctx) {
    int pid = bpf_get_current_pid_tgid() >> 32;

    long *count = bpf_map_lookup_elem(&execve_count, &pid);
    if (count) {
        (*count)++;
    } else {
        long new_count = 1;
        bpf_map_update_elem(&execve_count, &pid, &new_count, BPF_ANY);
    }

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
