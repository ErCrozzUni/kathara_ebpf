#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct flow_key {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
};

struct flow_stats {
    __u64 packet_count;
    __u64 byte_count;
    __u64 first_ts;
    __u64 last_ts;
    __u64 avg_pps;  // Average packets per second with precision up to 0.xxx
};

#define MY_IP bpf_htonl(0xC30B0E05)

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct flow_key);
    __type(value, struct flow_stats);
    __uint(max_entries, 1024);
} flow_map SEC(".maps");

SEC("xdp")
int count_udp_flows(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end) {
        return XDP_PASS;
    }

    if (iph->daddr != MY_IP) {
        return XDP_PASS;
    }

    if (iph->protocol != IPPROTO_UDP) {
        return XDP_PASS;
    }

    __u32 ip_hdr_len = iph->ihl * 4;
    struct udphdr *udph = (struct udphdr *)((void*)iph + ip_hdr_len);
    if ((void *)(udph + 1) > data_end) {
        return XDP_PASS;
    }

    struct flow_key key = {};
    key.saddr = iph->saddr;
    key.daddr = iph->daddr;
    key.sport = udph->source;
    key.dport = udph->dest;

    __u64 ip_len = bpf_ntohs(iph->tot_len);
    __u64 now = bpf_ktime_get_ns();

    struct flow_stats *stats = bpf_map_lookup_elem(&flow_map, &key);
    if (stats) {
        stats->packet_count += 1;
        stats->byte_count += ip_len;
        stats->last_ts = now;

        // Calcolo dell'average pps con precisione decimale
        if (stats->packet_count > 1) {
            __u64 duration_ns = stats->last_ts - stats->first_ts;
            if (duration_ns > 0) {
                // Moltiplica per 1000 per avere precisione a 0.xxx
                stats->avg_pps = (stats->packet_count * 1000000000ULL * 1000) / duration_ns;
            }
        }
    } else {
        // Primo pacchetto
        struct flow_stats new_stats = {};
        new_stats.packet_count = 1;
        new_stats.byte_count = ip_len;
        new_stats.first_ts = now;
        new_stats.last_ts = now;
        new_stats.avg_pps = 0;

        bpf_map_update_elem(&flow_map, &key, &new_stats, BPF_ANY);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
