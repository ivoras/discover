// wherez (Where Zee) lets you register and discover sibling nodes in the network
// based on a shared passphrase. It uses the Mainline DHT network to advertise
// its own existence and to look for other nodes that are running with the same
// passphrase.
//
// Wherez authenticates sibling peers using an HMAC-based mechanism.
//
// Example applications:
// - find the location of your company's doozerd, Chubby or DNS servers.
// - robust way for stolen notebooks to "phone home".
// - register and locate servers in a corporate network based on function, by
// using different passphrases for the DNS server, LDAP server, etc.
//
// This software is in early stages of development.
package discover

import (
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"log"
	"net"
	"strconv"
	"time"

	"github.com/nictuku/dht"
)

const DEFAULT_DHT_NODE = "213.239.195.138:40000"

/////////////////////////////////////////////////////////////////////////

type Peer struct {
	Addr string
}

func (p Peer) String() string {
	return fmt.Sprintf("%v", p.Addr)
}

/////////////////////////////////////////////////////////////////////////

// A discoverer uses the BitTorrent DHT network to find sibling
// nodes that are using the same passphrase. Wherez will listen on the
// specified port for both TCP and UDP protocols. The port must be accessible
// from the public Internet (UPnP is not supported yet).
//
// Wherez will try aggressively to find at least minPeers as fast as possible.
//
// The passphrase will be used to authenticate remote peers. This wherez node
// will keep running indefinitely as a DHT node.
//
// If appPort is a positive number, wherez will advertise that our main application
// is on port appPort of the current host. If it's negative, it doesn't
// announce itself as a peer.
type Discoverer struct {
	port            int
	appPort         int
	passphrase      []byte
	DiscoveredPeers chan Peer
	ih              dht.InfoHash

	*AuthClient
	*AuthServer
}

// create a new servie
func NewDiscoverer(port int, appPort int, passphrase []byte) (*Discoverer, error) {
	// infohash used for this wherez lookup. This should be somewhat hard to guess
	// but it's not exactly a secret.

	// SHA256 of the passphrase.
	h256 := sha256.New()
	h256.Write(passphrase)
	h := h256.Sum(nil)

	// Assuming perfect rainbow databases, it's better if the infohash does not
	// give out too much about the passphrase. Take half of this hash, then
	// generate a SHA1 hash from it.
	h2 := h[0 : sha256.Size/2]

	// Mainline DHT uses sha1.
	h160 := sha1.New()
	h160.Write(h2)
	h3 := h160.Sum(nil)
	ih := dht.InfoHash(h3[:])

	listenAddress := net.JoinHostPort("0.0.0.0", strconv.Itoa(port))

	authServer, sErr := NewAuthServer(listenAddress, appPort, passphrase)
	if sErr != nil {
		return nil, sErr
	}
	authClient, cErr := NewAuthClient(appPort, passphrase)
	if cErr != nil {
		return nil, cErr
	}

	d := &Discoverer{
		port:            port,
		appPort:         appPort,
		passphrase:      passphrase,
		DiscoveredPeers: make(chan Peer),
		ih:              ih,

		AuthServer: authServer,
		AuthClient: authClient,
	}

	return d, nil
}

// find authenticated peers
func (this *Discoverer) FindPeers(minPeers int) {
	defer close(this.DiscoveredPeers)

	announce := false
	if this.appPort > 0 {
		announce = true
		if err := this.ListenAndServe(); err != nil {
			log.Fatalf("Could not open listener:", err)
			return
		}
	}

	// Connect to the DHT network
	log.Println("Connecting to DHT network...")
	dhtService, err := dht.NewDHTNode(this.port, minPeers, announce)
	if err != nil {
		log.Println("Could not create the DHT node:", err)
		return
	}

	log.Printf("Adding DHT node %s...", DEFAULT_DHT_NODE)
	dhtService.AddNode(DEFAULT_DHT_NODE)

	go dhtService.DoDHT()

	// obtins peers (that can authenticate) from the DHT network
	go func(d *dht.DHT) {
		log.Printf("Waiting for possible peers...")
		for r := range d.PeersRequestResults {
			for _, peers := range r {
				for _, x := range peers {
					// A DHT peer for our infohash was found. It
					// needs to be authenticated.
					address := dht.DecodePeerAddress(x)
					log.Printf("Discovered possible peer %s", address)
					if response, err := this.Verify(address); err != nil || response == nil {
						log.Printf("Verification error: %s", err.Error())
					} else {
						host, _, err := net.SplitHostPort(address)
						if err != nil {
							log.Printf("could not parse address %s: %v", address, err)
						} else {
							peer := Peer{Addr: fmt.Sprintf("%v:%v", host, response.Port)}
							this.DiscoveredPeers <- peer
						}
					}
				}
			}
		}
	}(dhtService) // sends authenticated peers to channel c.

	for {
		// Keeps requesting for the infohash. This is a no-op if the
		// DHT is satisfied with the number of peers it has found.
		dhtService.PeersRequest(string(this.ih), true)
		time.Sleep(5 * time.Second)
	}
}
