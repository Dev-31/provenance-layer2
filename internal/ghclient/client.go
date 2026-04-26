// Package ghclient provides a GitHub App installation client for the
// provenance gateway. It handles manifest fetching, PR comment posting,
// and commit status updates.
package ghclient

import (
	"context"
	"fmt"
	"net/http"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/google/go-github/v63/github"
)

// Client wraps the authenticated GitHub App installation HTTP client and
// the go-github client built on top of it.
type Client struct {
	gh *github.Client
}

// New creates a GitHub App installation client authenticated via JWT.
// appID is the GitHub App ID, installationID is the installation ID for
// the target org/repo, and privateKeyPEM is the PEM-encoded RSA private key.
func New(appID, installationID int64, privateKeyPEM []byte) (*Client, error) {
	itr, err := ghinstallation.New(http.DefaultTransport, appID, installationID, privateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("ghclient: create installation transport: %w", err)
	}
	return &Client{
		gh: github.NewClient(&http.Client{Transport: itr}),
	}, nil
}

// FetchManifest retrieves .provenance/manifest.json from the given repo at ref.
// Returns the raw JSON bytes of the file content.
func (c *Client) FetchManifest(ctx context.Context, owner, repo, ref string) ([]byte, error) {
	opts := &github.RepositoryContentGetOptions{Ref: ref}
	fileContent, _, _, err := c.gh.Repositories.GetContents(ctx, owner, repo, ".provenance/manifest.json", opts)
	if err != nil {
		return nil, fmt.Errorf("ghclient: fetch manifest from %s/%s@%s: %w", owner, repo, ref, err)
	}
	if fileContent == nil {
		return nil, fmt.Errorf("ghclient: manifest not found in %s/%s@%s", owner, repo, ref)
	}

	// GetContent decodes the base64-encoded file content returned by the GitHub API.
	decoded, err := fileContent.GetContent()
	if err != nil {
		return nil, fmt.Errorf("ghclient: decode manifest content from %s/%s@%s: %w", owner, repo, ref, err)
	}
	if decoded == "" {
		return nil, fmt.Errorf("ghclient: empty manifest content in %s/%s@%s", owner, repo, ref)
	}
	return []byte(decoded), nil
}

// PostComment posts a PR comment to the given pull request.
func (c *Client) PostComment(ctx context.Context, owner, repo string, prNumber int, body string) error {
	comment := &github.IssueComment{Body: github.String(body)}
	_, _, err := c.gh.Issues.CreateComment(ctx, owner, repo, prNumber, comment)
	if err != nil {
		return fmt.Errorf("ghclient: post comment on %s/%s#%d: %w", owner, repo, prNumber, err)
	}
	return nil
}

// SetStatus sets the provenance/verify commit status on the given head SHA.
// state must be one of: "error", "failure", "pending", "success".
func (c *Client) SetStatus(ctx context.Context, owner, repo, headSHA, state, description string) error {
	status := &github.RepoStatus{
		State:       github.String(state),
		Description: github.String(description),
		Context:     github.String("provenance/verify"),
	}
	_, _, err := c.gh.Repositories.CreateStatus(ctx, owner, repo, headSHA, status)
	if err != nil {
		return fmt.Errorf("ghclient: set status on %s/%s@%s: %w", owner, repo, headSHA, err)
	}
	return nil
}
