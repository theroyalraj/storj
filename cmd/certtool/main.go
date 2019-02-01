package main

import (
	"fmt"
	"os"

	"storj.io/storj/pkg/identity"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <path/to/certfile.pem>\n", os.Args[0])
		os.Exit(1)
	}
	certFile := os.Args[1]
	nodeID, err := identity.NodeIDFromCertPath(certFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(2)
	}
	fmt.Printf("%s\n", nodeID.String())
}
