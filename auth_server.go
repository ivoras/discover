package discover

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"github.com/oxtoacart/bpool"
	"log"
	"net"
)

///////////////////////////////////////////////////////////////////////
// authentication server
///////////////////////////////////////////////////////////////////////

type AuthServer struct {
	AppPort    int
	Passphrase []byte

	address string

	tcpListener net.Listener
	udpListener *net.UDPConn

	udpPool *bpool.BytePool // a pool of buffers for reqding UDP requests
	// see also github.com/oxtoacart/bpool
}

// creates a new authentication server/client
func NewAuthServer(address string, appPort int, passphrase []byte) (*AuthServer, error) {
	// create a pool of buffers that we will use for reading from UDP
	pool := bpool.NewBytePool(LEN_UDP_POOLS, LEN_UDP_BUF)

	return &AuthServer{
		AppPort:    appPort,
		Passphrase: passphrase,
		address:    address,
		udpPool:    pool,
	}, nil
}

// start listening for TCP and UDP authentication requests
// this method can only be invoked once
func (a *AuthServer) ListenAndServe() error {
	if err := a.listenAndServeTCP(); err != nil {
		return err
	}
	if err := a.listenAndServeUDP(); err != nil {
		// TODO: send a message to the TCP listener for closing the connection
		return err
	}
	return nil
}

//////////////////////////
// private methods
//////////////////////////

// listen for TCP connections
func (a *AuthServer) listenAndServeTCP() error {
	if tcpaddr, err := net.ResolveTCPAddr("tcp", a.address); err != nil {
		return fmt.Errorf("could not resolve TCP address %s: %v", a.address, err)
	} else {
		log.Printf("Creating authentication TCP listeners on %s...", a.address)
		if tcpListener, err := net.ListenTCP("tcp", tcpaddr); err != nil {
			return fmt.Errorf("could not listen on TCP address %s: %v", a.address, err)
		} else {
			a.tcpListener = tcpListener

			go func() {
				defer a.tcpListener.Close()
				for {
					if conn, aErr := a.tcpListener.Accept(); aErr != nil {
						log.Println("TCP accept error. Stopping TCP listener:", aErr)
						return
					} else {
						go a.handleTCPClient(&conn)
					}
				}
			}()
		}
	}

	return nil
}

func (a *AuthServer) handleTCPClient(conn *net.Conn) {
	// Everything is done with one packet in and one packet out, so close
	// the connection after this function ends.
	defer (*conn).Close()

	// Parse the incoming packet.
	challenge := new(Challenge)
	err := binary.Read(*conn, binary.LittleEndian, challenge)
	if err != nil {
		return
	}
	response := Response{Port: uint16(a.AppPort)}
	a.respondChallenge(challenge, response)
	if err = binary.Write(*conn, binary.LittleEndian, response); err != nil {
		return
	}
}

// listen for UDP connections
func (a *AuthServer) listenAndServeUDP() error {
	if udpaddr, err := net.ResolveUDPAddr("udp", a.address); err != nil {
		return fmt.Errorf("could not resolve UDP address %s: %v", a.address, err)
	} else {
		log.Printf("Creating authentication UDP listeners on %s...", a.address)

		if udpListener, err := net.ListenUDP("udp", udpaddr); err != nil {
			// TODO: send a message to the TCP listener for closing the connection
			return fmt.Errorf("could not listen on UDP address %s: %v", a.address, err)
		} else {
			a.udpListener = udpListener

			go func(listener *net.UDPConn) {
				defer listener.Close()

				for {
					log.Printf("Reading from UDP socket...")
					buf := a.udpPool.Get()
					n, addr, uErr := listener.ReadFromUDP(buf)
					log.Printf("READ: %d", n)
					// TODO: control return values
					if uErr != nil {
						log.Println("UDP accept error. Stopping UDP listener:", uErr)
						a.udpPool.Put(buf)
						return
					} else if n > 0 {
						go a.handleUDPClient(addr, buf)
					} else {
						log.Printf("could not read from UDP socket: len=%d", n)
						a.udpPool.Put(buf)
					}

				}
			}(a.udpListener)

		}
	}

	return nil
}

// Handle an UDP client
func (a *AuthServer) handleUDPClient(addr *net.UDPAddr, bufPool []byte) {
	defer a.udpPool.Put(bufPool)

	buf := bytes.NewBuffer(bufPool)

	// Parse the incoming packet.
	challenge := new(Challenge)
	err := binary.Read(buf, binary.LittleEndian, challenge)
	if err != nil {
		return
	}
	response := Response{Port: uint16(a.AppPort)}

	a.respondChallenge(challenge, response)

	wbuf := new(bytes.Buffer)
	if err = binary.Write(wbuf, binary.LittleEndian, response); err != nil {
		log.Println("failed to write to remote peer:", err)
		return
	}
	a.udpListener.WriteToUDP(wbuf.Bytes(), addr)
	// TODO: control partial writes/errors

}

func (a *AuthServer) respondChallenge(challenge *Challenge, response Response) error {
	// Verify if the magic header is correct. Several DHT nodes will connect
	// to whatever peer they believe exist, most likely to scrape their
	// content. But we're not BitTorrent clients, so we just close the
	// connection. This shouldn't cause damage to the network because we're
	// not pretending to be peers for a bittorrent infohash. So these
	// spurious incoming connections are from misbehaving clients.
	if !bytes.Equal(challenge.MagicHeader[:], magicHeader) {
		// Not a wherez peer.
		log.Print("magic does not match: not a peer")
		return nil
	}

	// dedupe is a small byte array generated on initialization that
	// identifies this server. If the incoming request has the same dedupe ID,
	// it means it's trying to connect to itself. That's a normal thing, but
	// obviously useless, so close the connection.
	// To blacklist the address on the client side, the protocol would have
	// to have another step for the error feedback and for now that doesn't
	// seem worth it.
	if !allowSelfConnection && bytes.Equal(challenge.Dedupe[:], dedupe) {
		// Connection to self. Closing.
		log.Print("self-connecting")
		return nil
	}

	// Calculate the challenge response.
	mac := hmac.New(sha256.New, a.Passphrase)
	mac.Write(challenge.Challenge[:])

	// Create the response packet.
	copy(response.MAC[:], mac.Sum(nil))
	return nil
}
