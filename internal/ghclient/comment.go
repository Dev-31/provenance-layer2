package ghclient

import (
	"fmt"
	"strings"

	"github.com/Dev-31/provenance-layer1/manifest"
	"github.com/Dev-31/provenance-layer2/internal/verify"
)

const (
	verdictApproved        = "**APPROVED** 🟢"
	verdictTampered        = "**TAMPERED** 🔴"
	verdictUnverified      = "**UNVERIFIED** 🟡"
	verdictNoManifest      = "**NO MANIFEST** ⚪"
	verdictHeadSHAMismatch = "**HEAD SHA MISMATCH** ⚠️"
)

// FormatComment generates a Markdown PR comment body from a verify.Result.
// It renders a details table and a verdict section.
func FormatComment(result verify.Result) string {
	var sb strings.Builder

	sb.WriteString("## Provenance Verification\n\n")

	switch result.Status {
	case verify.StatusNoManifest:
		sb.WriteString(fmt.Sprintf("**Verdict:** %s\n\n", verdictNoManifest))
		sb.WriteString("> No `.provenance/manifest.json` was found for this pull request.\n")
		if result.Reason != "" {
			sb.WriteString(fmt.Sprintf("\n**Reason:** %s\n", result.Reason))
		}
		return sb.String()

	case verify.StatusTampered:
		sb.WriteString(fmt.Sprintf("**Verdict:** %s\n\n", verdictTampered))
		if result.Reason != "" {
			sb.WriteString(fmt.Sprintf("**Reason:** %s\n", result.Reason))
		}
		if result.Manifest != nil {
			sb.WriteString("\n")
			writeManifestTable(&sb, result.Manifest)
		}
		return sb.String()
	}

	// For APPROVED, UNVERIFIED, and HEAD SHA MISMATCH we have a manifest.
	m := result.Manifest

	if m != nil {
		writeManifestTable(&sb, m)
		sb.WriteString("\n")
	}

	// Determine the verdict.
	var verdict string
	switch {
	case result.Status == verify.StatusApproved && !result.HeadSHAMatch:
		verdict = verdictHeadSHAMismatch
	case result.Status == verify.StatusApproved:
		verdict = verdictApproved
	case result.Status == verify.StatusUnverified:
		verdict = verdictUnverified
	default:
		verdict = fmt.Sprintf("**%s**", result.Status)
	}

	sb.WriteString(fmt.Sprintf("**Verdict:** %s\n", verdict))

	if result.Reason != "" {
		sb.WriteString(fmt.Sprintf("\n**Reason:** %s\n", result.Reason))
	}

	return sb.String()
}

// writeManifestTable appends a Markdown details table to sb.
func writeManifestTable(sb *strings.Builder, m *manifest.Manifest) {
	sb.WriteString("| Field | Value |\n")
	sb.WriteString("|---|---|\n")

	// Agent
	sb.WriteString(fmt.Sprintf("| Agent | `%s` |\n", m.Agent.ID))
	sb.WriteString(fmt.Sprintf("| Provider | `%s` |\n", m.Agent.Provider))

	// Signed timestamp
	ts := m.Invocation.TimestampUTC
	if ts == "" {
		ts = "—"
	}
	sb.WriteString(fmt.Sprintf("| Signed timestamp | `%s` |\n", ts))

	// Key ID (from signature if present)
	keyID := "—"
	if m.Signature != nil && m.Signature.Kid != "" {
		keyID = m.Signature.Kid
	}
	sb.WriteString(fmt.Sprintf("| Key ID | `%s` |\n", keyID))

	// Tests
	testResult := testsCell(m.Verification)
	sb.WriteString(fmt.Sprintf("| Tests | %s |\n", testResult))

	// Human in loop
	humanInLoop := "No"
	if m.Invocation.HumanInLoop {
		humanInLoop = "Yes"
	}
	sb.WriteString(fmt.Sprintf("| Human in loop | %s |\n", humanInLoop))

	// Head SHA match — only show if PR info is present
	if m.PR != nil && m.PR.HeadSHA != "" {
		sb.WriteString(fmt.Sprintf("| Head SHA (manifest) | `%s` |\n", m.PR.HeadSHA))
	}
}

// testsCell returns the appropriate emoji + label for the verification cell.
func testsCell(v manifest.VerificationInfo) string {
	if !v.TestsRun {
		return "⏭ Not run"
	}
	if v.TestExitCode == 0 {
		label := "PASS"
		if v.DurationMs > 0 {
			label = fmt.Sprintf("PASS (%dms)", v.DurationMs)
		}
		return fmt.Sprintf("✅ %s", label)
	}
	return fmt.Sprintf("❌ FAIL (exit %d)", v.TestExitCode)
}
