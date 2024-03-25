
#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
// #include <bpf/libbpf.h>

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} execve_count SEC(".maps");

struct RingBufferData {
    int index;
    char data[12];
};

SEC("kprobe/__x64_sys_execve")
int sys_execve_perf_buffer(struct pt_regs *ctx) {
    int pid = bpf_get_current_pid_tgid() >> 32;
    // char data[] = "kprobe/__x64_sys_execve perf_buffer";
    struct RingBufferData *e;

    e = bpf_ringbuf_reserve(&execve_count, sizeof(*e), 0);
    if (!e) return 0;
    e->index = pid;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
