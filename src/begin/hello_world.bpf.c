#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// SEC("kprobe/sys_execve")
// int hello(struct pt_regs *ctx) {
//     bpf_printk("kprobe/sys_execve Hello World\n");
//     return 0;
// }

// char _license[] SEC("license") = "GPL";


// SEC("tracepoint/syscalls/sys_enter_execve")
// int bpf_prog(void *ctx) {
//     bpf_printk("kprobe/sys_execve Hello World\n");
//     return 0;
// }

SEC("kprobe/vfs_read")
int BPF_KPROBE(vfs_read_entry)
{
    bpf_printk("hello  world\n");
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
