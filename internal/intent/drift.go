package intent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	VerdictMatches = "MATCHES"
	VerdictDrifts  = "DRIFTS"
	VerdictUnclear = "UNCLEAR"
)

type Result struct {
	Verdict string
	Reason  string
}

// Check asks the OpenClaw LLM gateway whether prDiff implements what issueBody asked for.
// Never returns an error — on any failure returns Result{UNCLEAR, reason}.
func Check(ctx context.Context, issueBody, prDiff string) Result {
	endpoint := os.Getenv("OPENCLAW_ENDPOINT")
	if endpoint == "" {
		return Result{VerdictUnclear, "OPENCLAW_ENDPOINT not configured"}
	}

	prompt := fmt.Sprintf(
		"You are an intent-drift detector for AI-submitted pull requests.\n\n"+
			"Issue description:\n%s\n\n"+
			"PR diff (truncated to 3000 chars):\n%s\n\n"+
			"Does the PR implement what the issue asked for?\n"+
			"Reply with exactly one of:\n"+
			"MATCHES: <one sentence why>\n"+
			"DRIFTS: <one sentence why>\n"+
			"UNCLEAR: <one sentence why>",
		issueBody, truncate(prDiff, 3000),
	)

	reqBody, _ := json.Marshal(map[string]interface{}{
		"model": "gemini-flash-2.0",
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
	})

	httpReq, err := http.NewRequestWithContext(ctx, "POST",
		endpoint+"/v1/chat/completions", bytes.NewReader(reqBody))
	if err != nil {
		return Result{VerdictUnclear, fmt.Sprintf("build request: %v", err)}
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if key := os.Getenv("OPENCLAW_API_KEY"); key != "" {
		httpReq.Header.Set("Authorization", "Bearer "+key)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return Result{VerdictUnclear, fmt.Sprintf("LLM call failed: %v", err)}
	}
	defer resp.Body.Close()

	var apiResp struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return Result{VerdictUnclear, fmt.Sprintf("decode response: %v", err)}
	}
	if len(apiResp.Choices) == 0 {
		return Result{VerdictUnclear, "empty response from LLM"}
	}

	return parse(apiResp.Choices[0].Message.Content)
}

func parse(s string) Result {
	s = strings.TrimSpace(s)
	for _, verdict := range []string{VerdictMatches, VerdictDrifts, VerdictUnclear} {
		prefix := verdict + ":"
		if strings.HasPrefix(s, prefix) {
			return Result{
				Verdict: verdict,
				Reason:  strings.TrimSpace(strings.TrimPrefix(s, prefix)),
			}
		}
	}
	return Result{VerdictUnclear, s}
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "...(truncated)"
}
