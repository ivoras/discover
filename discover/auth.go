package discover

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
)

var (
	// Identifies wherez TCP messages.
	magicHeader = []byte("wherez")

	// dedupe is needed to ignore connections from self.
	dedupe []byte

	// If true, connections to self are allowed - used for testing.
	allowSelfConnection = false
)

const (
	messageLen = 20
	dedupeLen  = 10
)

///////////////////////////////////////////////////////////////////////////

func randMsg() ([]byte, error) {
	b := make([]byte, 20)
	_, err := rand.Read(b)
	return b, err
}

func init() {
	var err error
	dedupe, err = randMsg()
	if err != nil {
		log.Fatalln("could not generate a dedupe id:", err)
	}
	dedupe = dedupe[0:dedupeLen]
}

// Connect on that peer's TCP port and authenticate. Alice starts a
// conversation with Bob.
//
// A: Provides a challenge.
// B: Provides a response, authenticated with the shared secret.
//
// A: Requests port number information.
// B: Provides the application port number.
//
// Result: Alice now knows that bob:portX is a valid member of the connection pool.
//
// In the real world, the above is done in only one message each way. Protocol:
// - sends initial messsage of 36 bytes, containing:
//   ~ magicHeader with "wherez" ASCII encoded.
//   ~ 10 byte dedupe ID, which the remote node uses to identify
//   connection to self.
//   ~ 20 bytes challenge.
// - the other endpoint sends a 20 bytes message containing 2 bytes
// relative to the application port, plus 32 bytes of message MAC, calculated from
// the 20 bytes of client challenge.
// The MAC should be generated using the shared passphrase.

type Challenge struct {
	MagicHeader [6]byte
	Dedupe      [10]byte
	Challenge   [20]byte
}

// Response containing proof that the server (Bob) knows the shared secret and
// the application port information required by the client.
type Response struct {
	Port uint16
	MAC  [32]byte // MAC of the Challenge sent by the client (Alice).
}

type AuthListener func(address string) (net.Listener, error)
type AuthDialer func(address string) (net.Conn, error)

type AuthResolver struct {
	Port       int
	AppPort    int
	Passphrase []byte

	listenerFactory AuthListener
	dialerFactory   AuthDialer
}

func NewAuthResolver(appPort int, passphrase []byte,
	listener AuthListener, dialer AuthDialer) *AuthResolver {
	return &AuthResolver{
		AppPort:         appPort,
		Passphrase:      passphrase,
		listenerFactory: listener,
		dialerFactory:   dialer}
}

// create a new authentication resolution service
func NewAuthResolverTCP(port, appPort int, passphrase []byte) *AuthResolver {

	// create two TCP factories, for listeners and for dialers
	tcpListener := func(address string) (net.Listener, error) {
		log.Printf("Creating TCP listener to %s...", address)
		return net.Listen("tcp", address)
	}
	tcpDialer := func(address string) (net.Conn, error) {
		log.Printf("Creating TCP connection to %s...", address)
		return net.Dial("tcp", address)
	}

	return &AuthResolver{port, appPort, passphrase, tcpListener, tcpDialer}
}

/////////////////////////////////////////
// incoming connections
/////////////////////////////////////////

// start listening at the port specified, waiting for peers that want to
// connect to us...
func (a *AuthResolver) ListenAndServe() (net.Addr, error) {
	listener, err := a.listenerFactory(fmt.Sprintf(":%d", a.Port))
	if err != nil {
		log.Fatalf("Could not create listener: %v", err)
	}

	go func() {
		for {
			conn, aErr := listener.Accept()
			if err != nil {
				log.Println("accept error. Stopping listener.", aErr)
				return
			}
			go a.handleConn(conn, a.AppPort, a.Passphrase)
		}
	}()

	return listener.Addr(), nil
}

func (a *AuthResolver) handleConn(conn io.ReadWriteCloser, appPort int, passphrase []byte) {
	// Everything is done with one packet in and one packet out, so close
	// the connection after this function ends.
	defer conn.Close()

	// Parse the incoming packet.
	in := new(Challenge)
	err := binary.Read(conn, binary.LittleEndian, in)
	if err != nil {
		return
	}

	// Verify if the magic header is correct. Several DHT nodes will connect
	// to whatever peer they believe exist, most likely to scrape their
	// content. But we're not BitTorrent clients, so we just close the
	// connection. This shouldn't cause damage to the network because we're
	// not pretending to be peers for a bittorrent infohash. So these
	// spurious incoming connections are from misbehaving clients.
	if !bytes.Equal(in.MagicHeader[:], magicHeader) {
		// Not a wherez peer.
		return
	}
	// dedupe is a small byte array generated on initialization that
	// identifies this server. If the incoming request has the same dedupe ID,
	// it means it's trying to connect to itself. That's a normal thing, but
	// obviously useless, so close the connection.
	// To blacklist the address on the client side, the protocol would have
	// to have another step for the error feedback and for now that doesn't
	// seem worth it.
	if !allowSelfConnection && bytes.Equal(in.Dedupe[:], dedupe) {
		// Connection to self. Closing.
		return
	}
	// Calculate the challenge response.
	mac := hmac.New(sha256.New, passphrase)
	mac.Write(in.Challenge[:])

	// Create the response packet.
	response := Response{Port: uint16(appPort)}
	copy(response.MAC[:], mac.Sum(nil))

	if err = binary.Write(conn, binary.LittleEndian, response); err != nil {
		// log.Println("handleConn failed to write to remote peer:", err)
		return
	}
}

/////////////////////////////////////////
// outgoing connections
/////////////////////////////////////////

// Verify connects to a host:port address specified in peer and sends it a
// cryptographic challenge. If the peer responds with a valid MAC that appears
// to have been generated with the shared secret in passphrase, consider it a
// valid Peer and returns the details. If the connection fails or the peer
// authentication fails, returns an error.
func (a *AuthResolver) Verify(addr string, c chan Peer) error {
	conn, err := a.dialerFactory(addr)
	if err != nil {
		return fmt.Errorf("could not create connection to %s: %v", addr, err)
	}
	defer conn.Close()

	var challenge Challenge
	challenge, err = a.newChallenge()
	if err != nil {
		return fmt.Errorf("auth newChallenge error %v", err)
	}

	if err = binary.Write(conn, binary.LittleEndian, challenge); err != nil {
		// The other side is either unreachable or we connected to
		// ourselves and closed the connection.
		return nil
	}

	in := new(Response)
	if err = binary.Read(conn, binary.LittleEndian, in); err != nil {
		return fmt.Errorf("auth could not read response from conn:", err)
	}

	if !a.checkMAC(challenge.Challenge[:], in.MAC[:], a.Passphrase) {
		return fmt.Errorf("Invalid challenge response")
	}

	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("could not parse address %s: %v", addr, err)
	}

	peer := Peer{Addr: fmt.Sprintf("%v:%v", host, in.Port)}
	c <- peer
	return nil
}

func (a *AuthResolver) newChallenge() (m Challenge, err error) {
	//m = Challenge{}
	copy(m.MagicHeader[:], magicHeader[:])
	copy(m.Dedupe[:], dedupe[:])
	challenge, err := randMsg()
	if err != nil {
		return
	}
	copy(m.Challenge[:], challenge[:])
	return
}

func (a *AuthResolver) checkMAC(message, messageMAC, key []byte) bool {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	expectedMAC := mac.Sum(nil)
	return hmac.Equal(messageMAC, expectedMAC)
}
