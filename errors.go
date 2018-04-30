package discover

import (
	"errors"
)

var (
	// could not resolve address
	ERR_INVALID_ADDR = errors.New("invalid address or resoultion error")

	// could not connect
	ERR_COULD_NOT_CONNECT = errors.New("could not connect")

	// could not send to remote peer
	ERR_COULD_NOT_SEND = errors.New("could not send to remote peer")

	// could not send to remote peer
	ERR_DID_NOT_RESPOND = errors.New("remote peer did not respond")

	// remote peer sent a response, but it was garbage
	ERR_IS_NOT_PEER = errors.New("could not understand remote peer response")

	// the peer failed the verification test
	ERR_DID_NOT_VERIFY = errors.New("did not pass the challenge/response")
)
