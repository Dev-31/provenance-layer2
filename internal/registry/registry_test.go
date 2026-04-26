package registry

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/require"
)

func generateTestPubKeyPEM(t *testing.T) (string, *ecdsa.PublicKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	block := &pem.Block{Type: "PUBLIC KEY", Bytes: der}
	return string(pem.EncodeToMemory(block)), &key.PublicKey
}

func TestLookupMissingKey(t *testing.T) {
	_, err := Lookup("unknown-agent")
	require.Error(t, err)
	require.Contains(t, err.Error(), "PROVENANCE_PUBKEY_UNKNOWN_AGENT")
}

func TestLookupEmptyAgentID(t *testing.T) {
	_, err := Lookup("")
	require.Error(t, err)
	require.Contains(t, err.Error(), "agent ID is empty")
}

func TestLookupFound(t *testing.T) {
	pemStr, origPub := generateTestPubKeyPEM(t)
	t.Setenv("PROVENANCE_PUBKEY_MY_AGENT", pemStr)

	pub, err := Lookup("my-agent")
	require.NoError(t, err)
	require.True(t, origPub.Equal(pub))
}

func TestSanitize(t *testing.T) {
	cases := map[string]string{
		"openclaw-executor": "OPENCLAW_EXECUTOR",
		"my.agent.v2":       "MY_AGENT_V2",
		"org/repo":          "ORG_REPO",
	}
	for input, want := range cases {
		require.Equal(t, want, sanitize(input))
	}
}
