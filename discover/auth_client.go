package discover

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"time"
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
	dedupe = dedupe[0:LEN_DEDUPE]
}

///////////////////////////////////////////////////////////////////////

type AuthClient struct {
	AppPort    int
	Passphrase []byte
	Timeout    int
}

// creates a new authentication server/client
func NewAuthClient(appPort int, passphrase []byte) (*AuthClient, error) {
	log.Printf("Creating authentication client")
	return &AuthClient{
		AppPort:    appPort,
		Passphrase: passphrase,
		Timeout:    DEFAULT_TIMEOUT,
	}, nil
}

// Verify connects to a host:port address specified in peer and sends it a
// cryptographic challenge. If the peer responds with a valid MAC that appears
// to have been generated with the shared secret in passphrase, consider it a
// valid Peer and returns the details. If the connection fails or the peer
// authentication fails, returns an error.
func (a *AuthClient) Verify(address string) (*Response, error) {
	return a.verifyUDP(address)
}

// Verify connects to a host:port address specified in peer and sends it a
// cryptographic challenge. If the peer responds with a valid MAC that appears
// to have been generated with the shared secret in passphrase, consider it a
// valid Peer and returns the details. If the connection fails or the peer
// authentication fails, returns an error.
func (a *AuthClient) verifyUDP(address string) (*Response, error) {
	log.Printf("Verifying %s UDP", address)
	if challenge, err := NewChallenge(); err != nil {
		return nil, fmt.Errorf("could not create a challenge: %v", err)
	} else {
		challengeBuf, _ := challenge.ToBuffer()
		if err := binary.Write(challengeBuf, binary.LittleEndian, challenge); err != nil {
			// The other side is either unreachable or we connected to
			// ourselves and closed the connection.
			return nil, ERR_IS_NOT_PEER
		} else {
			// send the challenge with UDP
			if udpAddr, err := net.ResolveUDPAddr("udp", address); err != nil {
				return nil, ERR_INVALID_ADDR
			} else {
				if udpConn, err := net.DialUDP("udp", nil, udpAddr); err != nil {
					return nil, ERR_COULD_NOT_CONNECT
				} else {
					// set the cleanup and some timeout for the connection
					defer udpConn.Close()
					udpConn.SetDeadline(time.Now().Add(300 * time.Millisecond))

					if _, err := udpConn.Write(challengeBuf.Bytes()); err != nil {
						// The other side is either unreachable or we connected to
						// ourselves and closed the connection.
						return nil, ERR_COULD_NOT_SEND
					} else {
						responseBuffer := new(bytes.Buffer)

						if _, _, err := udpConn.ReadFrom(responseBuffer.Bytes()); err != nil {
							return nil, ERR_DID_NOT_RESPOND
						} else {
							response, ok := challenge.VerifyResponse(responseBuffer, a.Passphrase)
							if ok {
								log.Printf("Found a valid peer at %s !!!", address)
								return response, nil
							} else {
								return nil, ERR_DID_NOT_VERIFY
							}
						}
					}
				}
			}
		}
	}

	return nil, nil
}
