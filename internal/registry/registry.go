package registry

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
)

// Lookup returns the registered ECDSA public key for agentID.
// Keys are stored as PEM in env var PROVENANCE_PUBKEY_<AGENT>
// where <AGENT> is agentID uppercased with hyphens/dots/slashes replaced by underscores.
func Lookup(agentID string) (*ecdsa.PublicKey, error) {
	if agentID == "" {
		return nil, fmt.Errorf("agent ID is empty — cannot look up public key")
	}
	envKey := "PROVENANCE_PUBKEY_" + sanitize(agentID)
	pemData := os.Getenv(envKey)
	if pemData == "" {
		return nil, fmt.Errorf("no public key registered for agent %q (set env var %s)", agentID, envKey)
	}
	return parsePublicKeyPEM([]byte(pemData))
}

func parsePublicKeyPEM(data []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("not a valid PUBLIC KEY PEM block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is not ECDSA (got %T)", pub)
	}
	return ecPub, nil
}

func sanitize(s string) string {
	return strings.ToUpper(strings.NewReplacer("-", "_", ".", "_", "/", "_", " ", "_").Replace(s))
}
