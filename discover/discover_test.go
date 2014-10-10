package discover

import (
	"fmt"
	"testing"
)

func DisabledTestFindPeers(t *testing.T) {
	d, err := NewDiscoverer(60000, 31337, []byte("wherezexample"))
	if err != nil {
		t.Fail()
	}

	c := FindPeers(1)
	for p := range c {
		t.Logf("Found %v", p.String())
		return
	}
}
