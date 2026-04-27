package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Dev-31/provenance-layer2/internal/verify"
	"github.com/stretchr/testify/require"
)

func signedPayload(t *testing.T, secret, body string) string {
	t.Helper()
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(body))
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func TestHandlerRejectsInvalidSignature(t *testing.T) {
	t.Setenv("GITHUB_WEBHOOK_SECRET", "test-secret")
	req := httptest.NewRequest("POST", "/webhooks/github", strings.NewReader(`{}`))
	req.Header.Set("X-GitHub-Event", "pull_request")
	req.Header.Set("X-Hub-Signature-256", "sha256=deadbeef")
	rr := httptest.NewRecorder()
	Handler(rr, req)
	require.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestHandlerAcceptsValidSignature(t *testing.T) {
	t.Setenv("GITHUB_WEBHOOK_SECRET", "test-secret")
	body := `{"action":"labeled"}`
	sig := signedPayload(t, "test-secret", body)
	req := httptest.NewRequest("POST", "/webhooks/github", strings.NewReader(body))
	req.Header.Set("X-GitHub-Event", "push")
	req.Header.Set("X-Hub-Signature-256", sig)
	rr := httptest.NewRecorder()
	Handler(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)
}

func TestHandlerIgnoresNonPREvents(t *testing.T) {
	body := `{"action":"push"}`
	req := httptest.NewRequest("POST", "/webhooks/github", strings.NewReader(body))
	req.Header.Set("X-GitHub-Event", "push")
	rr := httptest.NewRecorder()
	Handler(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)
}

func TestHandlerBadJSONBody(t *testing.T) {
	req := httptest.NewRequest("POST", "/webhooks/github", strings.NewReader("not-json"))
	req.Header.Set("X-GitHub-Event", "pull_request")
	rr := httptest.NewRecorder()
	Handler(rr, req)
	require.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestValidateHMAC(t *testing.T) {
	body := []byte("hello")
	mac := hmac.New(sha256.New, []byte("secret"))
	mac.Write(body)
	validHeader := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	require.True(t, validateHMAC("secret", validHeader, body))
	require.False(t, validateHMAC("secret", "sha256=bad", body))
	require.False(t, validateHMAC("secret", "invalid-format", body))
	require.True(t, validateHMAC("", "anything", body))
}

func TestExtractAgentID(t *testing.T) {
	cases := []struct {
		json string
		want string
	}{
		{`{"agent":{"id":"openclaw-executor"}}`, "openclaw-executor"},
		{`{"agent":{}}`, ""},
		{`{}`, ""},
		{`not-json`, ""},
	}
	for _, tc := range cases {
		require.Equal(t, tc.want, extractAgentID([]byte(tc.json)), fmt.Sprintf("input: %s", tc.json))
	}
}

func TestStatusFromResult(t *testing.T) {
	cases := []struct {
		status    string
		headMatch bool
		wantState string
	}{
		{verify.StatusApproved, true, "success"},
		{verify.StatusApproved, false, "failure"},
		{verify.StatusTampered, true, "failure"},
		{verify.StatusUnverified, true, "failure"},
		{verify.StatusNoManifest, true, "failure"},
	}
	for _, tc := range cases {
		result := verify.Result{Status: tc.status, HeadSHAMatch: tc.headMatch}
		state, _ := statusFromResult(result)
		require.Equal(t, tc.wantState, state, "status=%s headMatch=%v", tc.status, tc.headMatch)
	}
}
