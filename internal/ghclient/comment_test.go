package ghclient

import (
	"strings"
	"testing"

	"github.com/Dev-31/provenance-layer1/manifest"
	"github.com/Dev-31/provenance-layer1/signing"
	"github.com/Dev-31/provenance-layer2/internal/verify"
	"github.com/stretchr/testify/assert"
)

// sampleManifest returns a minimal Manifest for use in tests.
func sampleManifest() *manifest.Manifest {
	return &manifest.Manifest{
		SchemaVersion: manifest.SchemaVersion,
		PR: &manifest.PRInfo{
			Repo:    "Dev-31/example",
			Number:  42,
			HeadSHA: "abc123",
		},
		Agent: manifest.AgentInfo{
			ID:       "claude-code",
			Version:  "1.0.0",
			Provider: "anthropic",
		},
		Invocation: manifest.InvocationInfo{
			TimestampUTC: "2026-04-26T10:00:00Z",
			HumanInLoop:  true,
		},
		Verification: manifest.VerificationInfo{
			TestsRun:     true,
			TestExitCode: 0,
			DurationMs:   1234,
		},
		Signature: &signing.Signature{
			Alg:   "ES256",
			Kid:   "sha256:abcdef1234",
			Value: "dGVzdA==",
		},
	}
}

// TestFormatCommentApproved verifies the APPROVED verdict comment contains
// the agent name, provider, test timing, and the APPROVED marker.
func TestFormatCommentApproved(t *testing.T) {
	result := verify.Result{
		Status:       verify.StatusApproved,
		Reason:       "signature valid",
		Manifest:     sampleManifest(),
		HeadSHAMatch: true,
	}

	body := FormatComment(result)

	assert.Contains(t, body, "APPROVED", "expected APPROVED verdict")
	assert.Contains(t, body, "claude-code", "expected agent name")
	assert.Contains(t, body, "anthropic", "expected provider")
	assert.Contains(t, body, "1234ms", "expected test timing in ms")
	assert.Contains(t, body, "2026-04-26T10:00:00Z", "expected signed timestamp")
}

// TestFormatCommentTampered verifies the TAMPERED verdict comment contains
// the TAMPERED marker and the reason string.
func TestFormatCommentTampered(t *testing.T) {
	result := verify.Result{
		Status: verify.StatusTampered,
		Reason: "signature mismatch: invalid r value",
	}

	body := FormatComment(result)

	assert.Contains(t, body, "TAMPERED", "expected TAMPERED verdict")
	assert.Contains(t, body, "signature mismatch", "expected reason text")
}

// TestFormatCommentNoManifest verifies that a NO_MANIFEST result produces a
// comment containing the NO MANIFEST marker.
func TestFormatCommentNoManifest(t *testing.T) {
	result := verify.Result{
		Status: verify.StatusNoManifest,
		Reason: "file not found",
	}

	body := FormatComment(result)

	assert.Contains(t, body, "NO MANIFEST", "expected NO MANIFEST verdict")
}

// TestFormatCommentHeadSHAMismatch verifies that an APPROVED result with
// HeadSHAMatch=false produces a HEAD SHA MISMATCH verdict.
func TestFormatCommentHeadSHAMismatch(t *testing.T) {
	result := verify.Result{
		Status:       verify.StatusApproved,
		Reason:       "signature valid",
		Manifest:     sampleManifest(),
		HeadSHAMatch: false,
	}

	body := FormatComment(result)

	assert.True(t, strings.Contains(body, "HEAD SHA MISMATCH"),
		"expected HEAD SHA MISMATCH verdict, got:\n%s", body)
	assert.NotContains(t, body, "**APPROVED**", "should not show APPROVED when SHA mismatches")
}

// TestFormatCommentTestsNotRun verifies that a manifest with TestsRun=false
// renders "Not run" in the comment.
func TestFormatCommentTestsNotRun(t *testing.T) {
	m := sampleManifest()
	m.Verification = manifest.VerificationInfo{
		TestsRun: false,
	}

	result := verify.Result{
		Status:       verify.StatusApproved,
		Reason:       "signature valid",
		Manifest:     m,
		HeadSHAMatch: true,
	}

	body := FormatComment(result)

	assert.Contains(t, body, "Not run", "expected 'Not run' for tests not executed")
}
