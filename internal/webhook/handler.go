package webhook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/Dev-31/provenance-layer2/internal/ghclient"
	"github.com/Dev-31/provenance-layer2/internal/intent"
	"github.com/Dev-31/provenance-layer2/internal/registry"
	"github.com/Dev-31/provenance-layer2/internal/verify"
)

type prEvent struct {
	Action      string `json:"action"`
	PullRequest struct {
		Number int    `json:"number"`
		Body   string `json:"body"`
		Head   struct {
			SHA string `json:"sha"`
			Ref string `json:"ref"`
		} `json:"head"`
	} `json:"pull_request"`
	Repository struct {
		Name  string `json:"name"`
		Owner struct {
			Login string `json:"login"`
		} `json:"owner"`
	} `json:"repository"`
	Installation struct {
		ID int64 `json:"id"`
	} `json:"installation"`
}

func Handler(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}

	secret := os.Getenv("GITHUB_WEBHOOK_SECRET")
	if !validateHMAC(secret, r.Header.Get("X-Hub-Signature-256"), body) {
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}

	if r.Header.Get("X-GitHub-Event") != "pull_request" {
		w.WriteHeader(http.StatusOK)
		return
	}

	var evt prEvent
	if err := json.Unmarshal(body, &evt); err != nil {
		http.Error(w, "parse body", http.StatusBadRequest)
		return
	}

	switch evt.Action {
	case "opened", "synchronize", "reopened":
		go processPR(evt)
	}

	w.WriteHeader(http.StatusOK)
}

func processPR(evt prEvent) {
	ctx := context.Background()
	appID, _ := strconv.ParseInt(os.Getenv("GITHUB_APP_ID"), 10, 64)
	privateKey := []byte(os.Getenv("GITHUB_APP_PRIVATE_KEY"))

	client, err := ghclient.New(appID, evt.Installation.ID, privateKey)
	if err != nil {
		log.Printf("processPR: create client: %v", err)
		return
	}

	owner := evt.Repository.Owner.Login
	repo := evt.Repository.Name
	prNum := evt.PullRequest.Number
	headSHA := evt.PullRequest.Head.SHA
	headRef := evt.PullRequest.Head.Ref

	if err := client.SetStatus(ctx, owner, repo, headSHA, "pending", "Verifying provenance..."); err != nil {
		log.Printf("processPR: set pending status: %v", err)
	}

	manifestJSON, err := client.FetchManifest(ctx, owner, repo, headRef)
	if err != nil {
		result := verify.Result{Status: verify.StatusNoManifest, Reason: fmt.Sprintf("%v", err)}
		postAndSetStatus(ctx, client, owner, repo, prNum, headSHA, result)
		return
	}

	agentID := extractAgentID(manifestJSON)
	pubKey, err := registry.Lookup(agentID)
	if err != nil {
		result := verify.Result{
			Status: verify.StatusUnverified,
			Reason: fmt.Sprintf("agent public key not registered: %v", err),
		}
		postAndSetStatus(ctx, client, owner, repo, prNum, headSHA, result)
		return
	}

	result := verify.Verify(manifestJSON, pubKey, headSHA)
	driftResult := intent.Check(ctx, evt.PullRequest.Body, "")
	comment := ghclient.FormatCommentWithDrift(result, driftResult)
	if err := client.PostComment(ctx, owner, repo, prNum, comment); err != nil {
		log.Printf("postAndSetStatus: post comment: %v", err)
	}
	state, description := statusFromResult(result)
	if err := client.SetStatus(ctx, owner, repo, headSHA, state, description); err != nil {
		log.Printf("postAndSetStatus: set status: %v", err)
	}
}

func postAndSetStatus(ctx context.Context, client *ghclient.Client, owner, repo string, prNum int, headSHA string, result verify.Result) {
	comment := ghclient.FormatComment(result)
	if err := client.PostComment(ctx, owner, repo, prNum, comment); err != nil {
		log.Printf("postAndSetStatus: post comment: %v", err)
	}
	state, description := statusFromResult(result)
	if err := client.SetStatus(ctx, owner, repo, headSHA, state, description); err != nil {
		log.Printf("postAndSetStatus: set status: %v", err)
	}
}

func statusFromResult(result verify.Result) (state, description string) {
	switch result.Status {
	case verify.StatusApproved:
		if !result.HeadSHAMatch {
			return "failure", "Head SHA mismatch — code changed after signing"
		}
		return "success", "Provenance verified ✅"
	case verify.StatusTampered:
		return "failure", "Provenance manifest tampered 🔴"
	case verify.StatusUnverified:
		return "failure", result.Reason
	case verify.StatusNoManifest:
		return "failure", "No provenance manifest found"
	default:
		return "error", "Internal error"
	}
}

func extractAgentID(data []byte) string {
	var raw struct {
		Agent struct {
			ID string `json:"id"`
		} `json:"agent"`
	}
	json.Unmarshal(data, &raw)
	return raw.Agent.ID
}

func validateHMAC(secret, header string, body []byte) bool {
	if secret == "" {
		return true
	}
	if !strings.HasPrefix(header, "sha256=") {
		return false
	}
	sig, err := hex.DecodeString(strings.TrimPrefix(header, "sha256="))
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hmac.Equal(mac.Sum(nil), sig)
}
