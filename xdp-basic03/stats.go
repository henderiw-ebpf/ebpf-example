package main

type xdp_data_t struct {
	Pkts  uint64
	Bytes uint64
}

type XDPAction uint32

const (
	XDP_ABORTED XDPAction = iota
	XDP_DROP
	XDP_PASS
	XDP_TX
	XDP_REDIRECT
)

func (a XDPAction) String() string {
	switch a {
	case XDP_ABORTED:
		return "aborted"
	case XDP_DROP:
		return "drop"
	case XDP_PASS:
		return "pass"
	case XDP_TX:
		return "tx"
	case XDP_REDIRECT:
		return "redirect"
	}
	return "uknown"
}
