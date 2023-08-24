// This program demonstrates attaching an eBPF program to a network interface
// with XDP (eXpress Data Path). The program parses the IPv4 source address
// from packets and writes the packet count by IP to an LRU hash map.
// The userspace program (Go code in this file) prints the contents
// of the map to stdout every second.
// It is possible to modify the XDP program to drop or redirect packets
// as well -- give it a try!
// This example depends on bpf_link, available in Linux kernel version 5.7 or newer.
package main

import (
	"log"
	"net"
	"os"
	"time"

	"github.com/cilium/ebpf/link"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf ./bpf/xdp_prog_kern.c -- -I../headers

//const mapKeyPass uint32 = 2


func main() {
	if len(os.Args) < 2 {
		log.Fatalf("Please specify a network interface")
	}

	// Look up the network interface by name.
	ifaceName := os.Args[1]
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("lookup network iface %q: %s", ifaceName, err)
	}

	// Load pre-compiled programs into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

	// Attach the program.
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpStatsFunc,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("could not attach XDP program: %s", err)
	}
	defer l.Close()

	log.Printf("Attached XDP program to iface %q (index %d)", iface.Name, iface.Index)
	log.Printf("Press Ctrl-C to exit and remove the program")

	// Print the contents of the BPF hash map (source IP address -> packet count).
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		//var data xdp_data_t

		entries := objs.XdpStatsMap.Iterate()
		var key XDPAction
		var value []xdp_data_t
		log.Printf("#### itfce %s ####", ifaceName)
		for entries.Next(&key, &value) {
			// Some empty arrays like sockmap don't return any keys.
			p := uint64(0)
			b := uint64(0)
			for _, data := range value {
				p += data.Pkts
				b += data.Bytes
			}
			log.Printf("%s: pkts rx: %d, bytes: %d\n", key.String(), p, b)

		}
		/*
			if err := objs.XdpStatsMap.Lookup(mapKeyPass, &data); err != nil {
				log.Fatalf("reading map: %v", err)
			}
			if err := objs.XdpStatsMap.Lookup(mapKeyPass, &data); err != nil {
				log.Fatalf("reading map: %v", err)
			}
		*/
	}
}
