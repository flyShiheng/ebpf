
#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "test_map.h"

struct bpf_map_def SEC("maps") execve_count = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(int),
    .value_size = sizeof(long),
    .max_entries = 1024,
};

// SEC("syscall")
// int kprobe_execve(struct pt_regs *ctx) {
//     int pid = bpf_get_current_pid_tgid() >> 32;
//     long *count = bpf_map_lookup_elem(&execve_count, &pid);
//     if (count) {
//         (*count)++;
//     } else {
//         long new_count = 1;
//         bpf_map_update_elem(&execve_count, &pid, &new_count, BPF_ANY);
//     }
//     return 0;
// }

// char LICENSE[] SEC("license") = "Dual BSD/GPL";


SEC("kprobe/sys_execve")
int kprobe_bpf_prog_sys_execve(struct pt_regs *ctx) {
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

char _license[] SEC("license") = "GPL";
