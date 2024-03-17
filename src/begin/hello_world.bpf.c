#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("kprobe/__x64_sys_execve")
int sys_execve_hello(struct pt_regs *ctx) {
    bpf_printk("kprobe/sys_execve Hello World\n");
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
