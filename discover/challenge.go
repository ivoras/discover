package discover

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
)

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

func NewChallenge() (*Challenge, error) {
	m := Challenge{}
	copy(m.MagicHeader[:], magicHeader[:])
	copy(m.Dedupe[:], dedupe[:])
	challengeMsg, err := randMsg()
	if err != nil {
		return nil, err
	}
	copy(m.Challenge[:], challengeMsg[:])
	return &m, nil
}

// Obtain the challenge as a buffer, for sending to the remote peer
func (challenge *Challenge) ToBuffer() (*bytes.Buffer, error) {
	challengeBuf := new(bytes.Buffer)
	if err := binary.Write(challengeBuf, binary.LittleEndian, challenge); err != nil {
		// The other side is either unreachable or we connected to
		// ourselves and closed the connection.
		return nil, err
	}
	return challengeBuf, nil
}

// Verify a reponse that has been returned for this challenge
func (challenge *Challenge) VerifyResponse(responseBuffer *bytes.Buffer,
	passphrase []byte) (*Response, bool) {

	var response = new(Response)
	if err := binary.Read(responseBuffer, binary.LittleEndian, response); err != nil {
		return nil, false
	}

	var message, messageMAC []byte = challenge.Challenge[:], response.MAC[:]
	mac := hmac.New(sha256.New, passphrase)
	mac.Write(message)
	expectedMAC := mac.Sum(nil)

	if !hmac.Equal(messageMAC, expectedMAC) {
		return nil, false
	}
	return response, true
}
