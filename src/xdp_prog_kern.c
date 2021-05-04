/* SPDX-License-Identifier: GPL-3.0 */
#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <net/if.h>

#include "../common/parsing_helpers.h"
#include "../common/xdp_stats_kern_user.h"
#include "../common/xdp_stats_kern.h"

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

struct bpf_map_def SEC("maps") tx_port = {
	.type = BPF_MAP_TYPE_DEVMAP,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = 256,
};

struct bpf_map_def SEC("maps") redirect_params = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = ETH_ALEN,
	.value_size = ETH_ALEN,
	.max_entries = 1,
};

#define IPV6_FLOWINFO_MASK bpf_htonl(0x0FFFFFFF)

// IPv4 decrement TTL from include/net/ip.h
static __always_inline int ip_decrease_ttl(struct iphdr *iph) {
	__u32 check = iph->check;
	check += bpf_htons(0x0100);
	iph->check = (__u16)(check + (check >= 0xFFFF));
	return --iph->ttl;
}

// XDP forwarding handler
static int _xdp_fwd(struct xdp_md *ctx, int debug) {
    void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct bpf_fib_lookup fib_params = {};
	struct ethhdr *eth = data;
	struct ipv6hdr *ip6h;
	struct iphdr *iph;
	__u16 h_proto;
	__u64 nh_off;
	int rc;
	int action = XDP_PASS;

	nh_off = sizeof(*eth);
	if (data + nh_off > data_end) {
		action = XDP_DROP;
		goto out;
	}

	h_proto = eth->h_proto;
	if (h_proto == bpf_htons(ETH_P_IP)) {
		iph = data + nh_off;

		if (iph + 1 > data_end) {
			action = XDP_DROP;
			goto out;
		}

		if (iph->ttl <= 1)
			goto out;

		fib_params.family	= AF_INET;
		fib_params.tos		= iph->tos;
		fib_params.l4_protocol	= iph->protocol;
		fib_params.sport	= 0;
		fib_params.dport	= 0;
		fib_params.tot_len	= bpf_ntohs(iph->tot_len);
		fib_params.ipv4_src	= iph->saddr;
		fib_params.ipv4_dst	= iph->daddr;
	} else if (h_proto == bpf_htons(ETH_P_IPV6)) {
		struct in6_addr *src = (struct in6_addr *) fib_params.ipv6_src;
		struct in6_addr *dst = (struct in6_addr *) fib_params.ipv6_dst;

		ip6h = data + nh_off;
		if (ip6h + 1 > data_end) {
			action = XDP_DROP;
			goto out;
		}

		if (ip6h->hop_limit <= 1)
			goto out;

		fib_params.family	= AF_INET6;
		fib_params.flowinfo	= *(__be32 *) ip6h & IPV6_FLOWINFO_MASK;
		fib_params.l4_protocol	= ip6h->nexthdr;
		fib_params.sport	= 0;
		fib_params.dport	= 0;
		fib_params.tot_len	= bpf_ntohs(ip6h->payload_len);
		*src			= ip6h->saddr;
		*dst			= ip6h->daddr;
	} else {
		goto out;
	}

	fib_params.ifindex = ctx->ingress_ifindex;

	rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
	switch (rc) {
	case BPF_FIB_LKUP_RET_SUCCESS: // FIB lookup success
		if (h_proto == bpf_htons(ETH_P_IP))
			ip_decrease_ttl(iph);
		else if (h_proto == bpf_htons(ETH_P_IPV6))
			ip6h->hop_limit--;

		memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
		memcpy(eth->h_source, fib_params.smac, ETH_ALEN);
		action = bpf_redirect_map(&tx_port, fib_params.ifindex, 0);
		if (debug == 1) {
            bpf_printk("action %d src %d dst %d", action, fib_params.ipv4_src, fib_params.ipv4_dst);
        }
		break;
	case BPF_FIB_LKUP_RET_BLACKHOLE:
	case BPF_FIB_LKUP_RET_UNREACHABLE:
	case BPF_FIB_LKUP_RET_PROHIBIT:
		action = XDP_DROP;
		break;
	case BPF_FIB_LKUP_RET_NOT_FWDED:
	case BPF_FIB_LKUP_RET_FWD_DISABLED:
	case BPF_FIB_LKUP_RET_UNSUPP_LWT:
	case BPF_FIB_LKUP_RET_NO_NEIGH:
	case BPF_FIB_LKUP_RET_FRAG_NEEDED:
		break; // XDP_PASS
	}

    if (debug == 1) {
        bpf_printk("rc %d src %d dst %d", rc, fib_params.ipv4_src, fib_params.ipv4_dst);
    }

out:
	return xdp_stats_record_action(ctx, action);
}

// XDP functions need to have a different identifier than their SEC labels (the "_func" suffix)

// XDP router, debug disabled
SEC("xdp_rtr")
int xdp_rtr_func(struct xdp_md *ctx) {
	return _xdp_fwd(ctx, 0);
}

// XDP router, debug enabled
SEC("xdp_rtr_debug")
int xdp_rtr_debug_func(struct xdp_md *ctx) {
	return _xdp_fwd(ctx, 1);
}

// Pass to kernel
SEC("xdp_pass")
int xdp_pass_func(struct xdp_md *ctx) {
    return xdp_stats_record_action(ctx, XDP_PASS);
}

// Drop all packets
SEC("xdp_drop")
int xdp_drop_func(struct xdp_md *ctx) {
    return xdp_stats_record_action(ctx, XDP_DROP);
}

char _license[] SEC("license") = "GPL";
