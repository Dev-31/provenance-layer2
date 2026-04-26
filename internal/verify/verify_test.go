package verify

import (
	"encoding/json"
	"testing"

	"github.com/Dev-31/provenance-layer1/manifest"
	"github.com/Dev-31/provenance-layer1/signing"
	"github.com/stretchr/testify/require"
)

func signedManifestJSON(t *testing.T, s *signing.Signer, m *manifest.Manifest) []byte {
	t.Helper()
	payload, err := m.Payload()
	require.NoError(t, err)
	sig, err := s.Sign(payload)
	require.NoError(t, err)
	m.Signature = sig
	data, err := json.Marshal(m)
	require.NoError(t, err)
	return data
}

func baseManifest() *manifest.Manifest {
	return &manifest.Manifest{
		SchemaVersion: manifest.SchemaVersion,
		Agent:         manifest.AgentInfo{ID: "test-agent", Version: "1.0", Provider: "test"},
		Invocation:    manifest.InvocationInfo{TimestampUTC: "2026-04-26T12:00:00Z", WorkingDir: "/w"},
		Verification:  manifest.VerificationInfo{TestsRun: false},
	}
}

func TestVerifyApproved(t *testing.T) {
	signer, err := signing.NewSigner()
	require.NoError(t, err)
	data := signedManifestJSON(t, signer, baseManifest())
	result := Verify(data, signer.PublicKey(), "")
	require.Equal(t, StatusApproved, result.Status)
	require.True(t, result.HeadSHAMatch)
	require.NotNil(t, result.Manifest)
}

func TestVerifyNoSignature(t *testing.T) {
	m := baseManifest()
	data, _ := json.Marshal(m)
	signer, _ := signing.NewSigner()
	result := Verify(data, signer.PublicKey(), "")
	require.Equal(t, StatusUnverified, result.Status)
}

func TestVerifyBadJSON(t *testing.T) {
	signer, _ := signing.NewSigner()
	result := Verify([]byte("not json"), signer.PublicKey(), "")
	require.Equal(t, StatusTampered, result.Status)
}

func TestVerifyWrongKey(t *testing.T) {
	signer1, _ := signing.NewSigner()
	signer2, _ := signing.NewSigner()
	data := signedManifestJSON(t, signer1, baseManifest())
	result := Verify(data, signer2.PublicKey(), "")
	require.Equal(t, StatusTampered, result.Status)
}

func TestVerifyTamperedField(t *testing.T) {
	signer, _ := signing.NewSigner()
	m := baseManifest()
	m.Verification = manifest.VerificationInfo{TestsRun: true, TestExitCode: 0}
	data := signedManifestJSON(t, signer, m)

	var raw map[string]interface{}
	json.Unmarshal(data, &raw)
	if v, ok := raw["verification"].(map[string]interface{}); ok {
		v["test_exit_code"] = 1
	}
	tamperedData, _ := json.Marshal(raw)

	result := Verify(tamperedData, signer.PublicKey(), "")
	require.Equal(t, StatusTampered, result.Status)
}

func TestVerifyUnknownSchemaVersion(t *testing.T) {
	signer, _ := signing.NewSigner()
	m := baseManifest()
	m.SchemaVersion = "99.0"
	data := signedManifestJSON(t, signer, m)
	result := Verify(data, signer.PublicKey(), "")
	require.Equal(t, StatusUnverified, result.Status)
	require.Contains(t, result.Reason, "99.0")
}

func TestVerifyHeadSHAMatch(t *testing.T) {
	signer, _ := signing.NewSigner()
	m := baseManifest()
	// manifest.PRInfo exists with HeadSHA field; test no-PR path (defaults to true)
	data := signedManifestJSON(t, signer, m)
	result := Verify(data, signer.PublicKey(), "abc123")
	require.Equal(t, StatusApproved, result.Status)
	require.True(t, result.HeadSHAMatch) // no PR field → defaults to true
}

func TestVerifyHeadSHAMismatch(t *testing.T) {
	signer, _ := signing.NewSigner()
	m := baseManifest()
	m.PR = &manifest.PRInfo{Repo: "Dev-31/repo", Number: 1, HeadSHA: "aaa111"}
	data := signedManifestJSON(t, signer, m)
	result := Verify(data, signer.PublicKey(), "bbb222")
	require.Equal(t, StatusApproved, result.Status) // signature still valid
	require.False(t, result.HeadSHAMatch)            // but SHA doesn't match
}

func TestVerifyHeadSHAExact(t *testing.T) {
	signer, _ := signing.NewSigner()
	m := baseManifest()
	m.PR = &manifest.PRInfo{Repo: "Dev-31/repo", Number: 2, HeadSHA: "deadbeef"}
	data := signedManifestJSON(t, signer, m)
	result := Verify(data, signer.PublicKey(), "deadbeef")
	require.Equal(t, StatusApproved, result.Status)
	require.True(t, result.HeadSHAMatch)
}
