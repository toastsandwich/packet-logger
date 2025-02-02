// cgo: ignore
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>

#include <bpf/bpf_helpers.h>

struct {
  __uint(type, BPF_MAP_TYPE_HASH); // set type of map
  __uint(max_entries, 1024);       // set the max entries
  __type(key, __be32);             // set type for key
  __type(value, __u64);            // set type of value
} xdp_map SEC(".maps");            // give the map a name and add to a sec

SEC("xdp")
int xdp_logger(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end) {
    return XDP_PASS;
  }

  struct iphdr *ip = (struct iphdr *)(eth + 1);
  if ((void *)(ip + 1) > data_end) {
    return XDP_PASS;
  }

  __be32 src_ip = ip->saddr;
  __u64 *cnt = bpf_map_lookup_elem(&xdp_map, &src_ip);
  if (cnt) {
    __sync_fetch_and_add(cnt, 1);
  } else {
    __u64 init_cnt = 1;
    bpf_map_update_elem(&xdp_map, &src_ip, &init_cnt, BPF_ANY);
  }
  return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
