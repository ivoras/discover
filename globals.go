package discover

const (
	LEN_UDP_POOLS   = 100
	LEN_UDP_BUF     = 4096
	LEN_MSG         = 20
	LEN_DEDUPE      = 10
	DEFAULT_TIMEOUT = 300 // default timeout in milliseconds
)

// Identifies messages.
var magicHeader = []byte("XXUU7611")

// dedupe is needed to ignore connections from self.
var dedupe []byte

// If true, connections to self are allowed - used for testing.
var allowSelfConnection = false
