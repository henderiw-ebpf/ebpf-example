/* SPDX-License-Identifier: GPL-2.0 */
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <linux/icmp.h>
#include <bpf/helpers.h>
#include <bpf/bpf_endian.h>
/* Defines xdp_stats_map from packet04 */
#include "../common/xdp_stats_kern_user.h"
#include "../common/xdp_stats_kern.h"
#include "../common/parsing_helpers.h"

SEC("xdp_packet_parser")
int  xdp_parser_func(struct xdp_md *ctx)
{
  /* Default action XDP_PASS, imply everything we couldn't parse, or that
	 * we don't want to deal with, we just pass up the stack and let the
	 * kernel deal with it.
	 */
	int action = XDP_PASS; /* Default action */
  int eth_type, ip_type, icmp_type;
  struct ethhdr *eth;  
  //struct icmphdr *icmph;

  void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

  /* These keep track of the next header type and iterator pointer */
  /* Start next header cursor position at data start */
  struct hdr_cursor nh = { .pos = data };


	/* Packet parsing in steps: Get each header one at a time, aborting if
	 * parsing fails. Each helper function does sanity checking (is the
	 * header type in the packet correct?), and bounds checking.
	 */
	eth_type = parse_ethhdr(&nh, data_end, &eth);
  if (eth_type < 0) {
		action = XDP_ABORTED;
		goto out;
	}

	if (eth_type == bpf_htons(ETH_P_IPV6)) {
    struct ipv6hdr *ip6h; 
    struct icmp6hdr *icmp6h;

    ip_type = parse_ip6hdr(&nh, data_end, &ip6h);
		if (ip_type != IPPROTO_ICMPV6)
      goto out;
    
    icmp_type = parse_icmp6hdr(&nh, data_end, &icmp6h);
    if (icmp_type != ICMPV6_ECHO_REQUEST)
      goto out;
    
    if (bpf_ntohs(icmp6h->icmp6_sequence) % 2 == 0)
      action = XDP_DROP;
  } else if (eth_type == bpf_htons(ETH_P_IP)) {
    struct iphdr *iph;
		struct icmphdr *icmph;

		ip_type = parse_iphdr(&nh, data_end, &iph);
		if (ip_type != IPPROTO_ICMP)
			goto out;
  
    icmp_type = parse_icmphdr(&nh, data_end, &icmph);
    if (icmp_type != ICMP_ECHO)
      goto out;
    
    if (bpf_ntohs(icmph->un.echo.sequence) % 2 == 0)
      action = XDP_DROP;
  }
out:
	return xdp_stats_record_action(ctx, action); /* read via xdp_stats */
}

char _license[] SEC("license") = "GPL";