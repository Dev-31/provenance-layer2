# Provenance Gateway — Setup

## 1. Register the GitHub App

1. Go to https://github.com/settings/apps/new
2. Set **Webhook URL** to `https://<your-host>/webhooks/github`
3. Set **Webhook secret** (random string, save for env)
4. Grant permissions:
   - Pull requests: Read & Write
   - Commit statuses: Read & Write
   - Contents: Read
5. Subscribe to event: **Pull request**
6. Generate a **Private key** (download `.pem` file)
7. Note the **App ID** from the app settings page

## 2. Enroll agent public keys

For each AI agent that will sign manifests, export its public key and set the env var:

```bash
# On the agent's machine:
provenance-sign pubkey --key ~/.provenance/signing.key

# Copy the PEM output and set:
export PROVENANCE_PUBKEY_OPENCLAW_EXECUTOR="<pem output>"
```

## 3. Configure environment

Copy `.env.example` to `.env` and fill in all values.

## 4. Run the gateway

```bash
go build -o provenance-gateway ./cmd/provenance-gateway/
source .env
./provenance-gateway
```

The gateway listens on `:8080` (or `$PORT`) and is ready to receive webhooks.

## 5. Install the App on your repo

In your GitHub App settings, install the app on the repositories where AI agents submit PRs.
