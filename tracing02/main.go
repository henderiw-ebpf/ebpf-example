package main

import (
	"fmt"
	"log"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf ./bpf/trace_prog_kern.c -- -I../headers

const mapKey uint32 = 0

func main() {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// Open a tracepoint and attach the pre-compiled program. Each time
	// the kernel function enters, the program will increment the execution
	// counter by 1. The read loop below polls this map value once per
	// second.
	// The first two arguments are taken from the following pathname:
	// /sys/kernel/debug/tracing/events/kmem/mm_page_alloc
	link, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "xdp trace exception",
		Program: objs.TraceXdpException,
	})
	if err != nil {
		log.Fatalf("attach raw tracepoint error: %v", err)
	}
	info, err := link.Info()
	if err != nil {
		log.Fatalf("link info error: %v", err)
	}

	defer link.Close()

	// Read loop reporting the total amount of times the kernel
	// function was entered, once per second.
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	log.Println("Waiting for events..")
	for range ticker.C {
		fmt.Printf("info: %v\n", info)
		entries := objs.ExceptionCnt.Iterate()
		var key int32
		var value []uint64

		for entries.Next(&key, &value) {
			fmt.Printf("key %d, value: %d\n", key, value)
		}
	}
}
