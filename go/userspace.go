package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

const EBPF_OBJ_PATH = "./../packet_logger.bpf.o"

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}
	collc, err := ebpf.LoadCollection(EBPF_OBJ_PATH)
	if err != nil {
		log.Fatal(err)
	}
	xdp_map := collc.Maps["xdp_map"]
	if xdp_map == nil {
		log.Fatal("map was not found")
	}

	iface, err := net.InterfaceByName("wlp0s20f3")
	if err != nil {
		log.Fatal(err)
	}

	link, err := link.AttachXDP(link.XDPOptions{
		Program:   collc.Programs["xdp_logger"],
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer link.Close()
	fmt.Println("attached to kernel")
	fmt.Println("to detach Ctrl + C....")

	stop := make(chan os.Signal, 1)
	signal.Notify(stop,
		os.Interrupt,
		syscall.SIGSTOP,
		syscall.SIGTERM,
	)

	seen := make(map[uint32]uint64)
	mu := sync.Mutex{}
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				PrintStat(xdp_map, &mu, seen)
			case <-stop:
				return
			}
		}
	}()
	<-stop
	fmt.Println("detaching program..")
}

func PrintStat(xdp_map *ebpf.Map, mu *sync.Mutex, seen map[uint32]uint64) {
	for {
		iter := xdp_map.Iterate()
		var key uint32
		var val uint64

		fmt.Print("\033[H\033[J")
		mu.Lock()

		updated := false
		for iter.Next(&key, &val) {
			seen[key] = val
			updated = true
		}

		for k, v := range seen {
			ip := GetIP(k)
			names, err := net.LookupAddr(ip)
			if err != nil {
				fmt.Printf("\r%s: %d\n", ip, v)
			} else {
				fmt.Printf("\r%v: %d [ip: %s]\n", names, v, ip)
			}
		}
		fmt.Printf("\r")
		mu.Unlock()
		if updated {
			time.Sleep(1 * time.Second)
		}
	}
}

func GetIP(ip uint32) string {
	_ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(_ip, ip)
	return _ip.String()
}
