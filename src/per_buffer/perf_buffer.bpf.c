
#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} execve_count SEC(".maps");

SEC("kprobe/__x64_sys_execve")
int sys_execve_perf_buffer(struct pt_regs *ctx) {
    // int pid = bpf_get_current_pid_tgid() >> 32;
    char data[] = "kprobe/__x64_sys_execve perf_buffer";

    bpf_perf_event_output(ctx, &execve_count, BPF_F_CURRENT_CPU, &data, sizeof(data));
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
