package verify

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"

	"github.com/Dev-31/provenance-layer1/manifest"
	"github.com/Dev-31/provenance-layer1/signing"
)

const (
	StatusApproved   = "APPROVED"
	StatusTampered   = "TAMPERED"
	StatusUnverified = "UNVERIFIED"
	StatusNoManifest = "NO_MANIFEST"
)

type Result struct {
	Status       string
	Reason       string
	Manifest     *manifest.Manifest
	HeadSHAMatch bool
}

func Verify(manifestJSON []byte, registeredPubKey *ecdsa.PublicKey, actualHeadSHA string) Result {
	var m manifest.Manifest
	if err := json.Unmarshal(manifestJSON, &m); err != nil {
		return Result{Status: StatusTampered, Reason: fmt.Sprintf("invalid JSON: %v", err)}
	}

	if m.Signature == nil {
		return Result{Status: StatusUnverified, Reason: "manifest has no signature", Manifest: &m}
	}

	if m.SchemaVersion != manifest.SchemaVersion {
		return Result{
			Status:   StatusUnverified,
			Reason:   fmt.Sprintf("unsupported schema version %q (want %q)", m.SchemaVersion, manifest.SchemaVersion),
			Manifest: &m,
		}
	}

	payload, err := m.Payload()
	if err != nil {
		return Result{Status: StatusTampered, Reason: fmt.Sprintf("canonicalize error: %v", err)}
	}

	if err := signing.Verify(payload, m.Signature, registeredPubKey); err != nil {
		return Result{Status: StatusTampered, Reason: err.Error(), Manifest: &m}
	}

	headSHAMatch := true
	if m.PR != nil && m.PR.HeadSHA != "" && actualHeadSHA != "" {
		headSHAMatch = m.PR.HeadSHA == actualHeadSHA
	}

	return Result{
		Status:       StatusApproved,
		Reason:       "signature valid",
		Manifest:     &m,
		HeadSHAMatch: headSHAMatch,
	}
}
