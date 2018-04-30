package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"runtime/pprof"
	"strconv"

	"github.com/ccding/go-stun/stun"
	"github.com/ivoras/discover"
)

var ERR_COULD_NOT_OBTAIN = fmt.Errorf("Could not obtain a valid IP/port")

const STUN_SERVICE_ADDR = "stun.ekiga.net"
const STUN_SERVICE_PORT = 3478

func main() {
	var cpuprofile = flag.String("cpuprofile", "", "write cpu profile to file")
	flag.Parse()
	if len(flag.Args()) != 2 {
		log.Fatalln("Usage: discover [options] <app port> <passphrase>")
	}
	appPort, err := strconv.Atoi(flag.Arg(0))
	if err != nil {
		log.Fatalf("Invalid port parameter: %v", err)
	}
	passphrase := flag.Arg(1)

	// get an external IP:port
	err = nil
	var stunHost *stun.Host

	if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			log.Fatal(err)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	log.Printf("Using STUN for getting external IP from %s:%d...",
		STUN_SERVICE_ADDR, STUN_SERVICE_PORT)
	_, stunHost, err = stun.NewClient().Discover()
	if err != nil {
		log.Fatalf("Could not obtain IP:port with STUN")
	}
	if stunHost == nil {
		log.Fatalf("Could not obtain IP:port with STUN")
	}

	host, port := stunHost.IP(), int(stunHost.Port())
	log.Printf("External IP/port: %s:%d...", host, port)

	if dis, err := discover.NewDiscoverer(port, appPort, []byte(passphrase)); err != nil {
		log.Fatal("could not initialize discoverer", err)
	} else {
		dis.FindPeers(1)
		for p := range dis.DiscoveredPeers {
			// Peer found!
			fmt.Println("peer found:", p.String())
		}
	}
}
