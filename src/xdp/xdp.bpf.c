#include "/usr/include/linux/types.h"
#include "linux/bpf.h"
// #include <linux/in.h>
// #include <linux/if_ether.h>
// #include <linux/if_packet.h>
// #include <linux/if_vlan.h>
// #include <linux/ip.h>
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} execve_count SEC(".maps");

SEC("xdp")
int xdp_perf_buffer(struct xdp_md *ctx) {
    char data[] = "xdp perf_buffer";
    long protocol = lookup_protocol(ctx);
    if (protocol == 1) {
        bpf_printk("xdp_perf_buffer Hello ping\n");
    }
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
