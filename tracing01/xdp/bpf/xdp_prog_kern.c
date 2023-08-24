/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <bpf/helpers.h>

/* Defines xdp_stats_map */
#include "../common/xdp_stats_kern_user.h"
#include "../common/xdp_stats_kern.h"

SEC("xdp_abort")
int  xdp_drop_func(struct xdp_md *ctx)
{
  return xdp_stats_record_action(ctx, XDP_ABORTED);
}

char _license[] SEC("license") = "GPL";