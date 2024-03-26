#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include <linux/pkt_cls.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

#include <bpf/bpf_endian.h>

static __always_inline unsigned short is_icmp_ping_request(void *data,
                                                           void *data_end) {
  struct ethhdr *eth = data;
  if (data + sizeof(struct ethhdr) > data_end)
    return 0;

  if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
    return 0;

  struct iphdr *iph = data + sizeof(struct ethhdr);
  if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
    return 0;

  if (iph->protocol != 0x01)
    // We're only interested in ICMP packets
    return 0;

  struct icmphdr *icmp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
  if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) +
          sizeof(struct icmphdr) >
      data_end)
    return 0;

  return (icmp->type == 8);
}

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} execve_count SEC(".maps");

SEC("xdp")
int xdp_perf_buffer(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  if (is_icmp_ping_request(data, data_end)) {
        bpf_printk("Got ping packet");
        return XDP_PASS;
  }

  return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// int counter = 0;

// SEC("xdp")
// int xdp_perf_buffer(struct xdp_md *ctx) {
//     bpf_printk("Hello World %d", counter);
//     counter++; 
//     return XDP_PASS;
// }

// char LICENSE[] SEC("license") = "Dual BSD/GPL";
