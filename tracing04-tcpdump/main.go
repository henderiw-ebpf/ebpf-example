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
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -target bpfel bpf ./bpf/xdp_sample_pkts_kern.c -- -I../headers

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("Please specify a network interface and a action")
	}

	// Look up the network interface by name.
	ifaceName := os.Args[1]
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("lookup network iface %q: %s", ifaceName, err)
	}

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

	// Attach the program.
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpSampleProg,
		Interface: iface.Index,
	})

	if err != nil {
		log.Fatalf("could not attach XDP program: %s", err)
	}
	defer l.Close()

	log.Printf("Attached XDP program to iface %q (index %d)", iface.Name, iface.Index)
	log.Printf("Press Ctrl-C to exit and remove the program")

	f, err := os.Create("sample.pcap")
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
	defer f.Close()

	// Open a perf event reader from userspace on the PERF_EVENT_ARRAY map
	// described in the eBPF C program.
	rd, err := perf.NewReader(objs.MyMap, os.Getpagesize())
	if err != nil {
		log.Fatalf("creating perf event reader: %s", err)
	}
	defer rd.Close()

	go func() {
		// Wait for a signal and close the perf reader,
		// which will interrupt rd.Read() and make the program exit.
		<-stopper
		log.Println("Received signal, exiting program..")

		if err := rd.Close(); err != nil {
			log.Fatalf("closing perf event reader: %s", err)
		}
	}()

	log.Printf("Listening for events..")

	// bpfEvent is generated by bpf2go.
	w := pcapgo.NewWriter(f)
	w.WriteFileHeader(65536, layers.LinkTypeEthernet)

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			log.Printf("reading from perf event reader: %s", err)
			continue
		}

		if record.LostSamples != 0 {
			log.Printf("perf event ring buffer full, dropped %d samples", record.LostSamples)
			continue
		}

		lenBytes := make([]byte, 2, 2)
		lenBytes[0] = record.RawSample[2]
		lenBytes[1] = record.RawSample[3]

		l := binary.LittleEndian.Uint16(lenBytes)
		log.Printf("record length: %d, rawByte len: %d", l, len(record.RawSample))

		
		//var event bpfEvent
		log.Printf("new event")
		data := make([]byte, l, l)
		for i, b := range record.RawSample[4 : l+4] {
			data[i] = b
			fmt.Printf("%02x ", b)
		}
		fmt.Printf("\n")

		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.DecodeStreamsAsDatagrams)

		for _, layer := range packet.Layers() {
			fmt.Printf("PACKET LAYER: %v\n", layer.LayerType())
		}

		packet.Metadata().CaptureInfo.Length = len(data)
		packet.Metadata().CaptureInfo.CaptureLength = len(data)
		packet.Metadata().CaptureInfo.Timestamp = time.Now()
		//packet.Metadata().CaptureInfo.InterfaceIndex = 10

		log.Printf("packet capture info: %v", packet.Metadata().CaptureInfo.CaptureLength)

		
		
		w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())

		//log.Printf("event : %v", event)
	}
}
