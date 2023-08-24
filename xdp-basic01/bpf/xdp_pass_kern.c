/* SPDX-License-Identifier: GPL-2.0 */
// #include <linux/bpf.h>
//#include <bpf/bpf_helpers.h>
#include "bpf_endian.h"
#include "common.h"

SEC("xdp")
int  xdp_prog_simple(struct xdp_md *ctx)
{
	return XDP_PASS;
}