package main

import (
	"flag"
	"fmt"
	"log"
	"strconv"

	"github.com/inercia/wherez/discover"
)

// port for the wherez protocol (UDP+TCP).
const port = 40000

func main() {
	flag.Parse()
	if len(flag.Args()) != 2 {
		log.Fatalln("Usage: wherez [options] <app port> <passphrase>")
	}
	appPort, err := strconv.Atoi(flag.Arg(0))
	if err != nil {
		log.Fatalf("Invalid port parameter: %v", err)
	}
	passphrase := flag.Arg(1)

	var dis *discover.Discoverer
	dis , err = discover.NewDiscoverer(port, appPort, []byte(passphrase))
	dis.FindPeers(1)
	for p := range dis.DiscoveredPeers {
		// Peer found!
		fmt.Println("peer found:", p.String())
	}
}
