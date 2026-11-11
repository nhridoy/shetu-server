<h1 align="center">Shetu Server</h1>

<p align="center">
  The open-source sync server for <a href="https://shetu.iamnahid.com">Shetu</a>, the free SSH client and Termius alternative.<br>
  Run it yourself and keep accounts, encrypted vaults and team vaults on infrastructure you control.<br>
  <sub><i>Shetu</i> (সেতু) is Bengali for <i>bridge</i>. Say it SHAY-too.</sub>
</p>

<p align="center">
  <a href="https://shetu.iamnahid.com/self-hosted">Overview</a> ·
  <a href="https://shetu.iamnahid.com/docs/server">Self-hosting guide</a> ·
  <a href="https://shetu.iamnahid.com/docs/security">Security reference</a> ·
  <a href="https://github.com/nhridoy/shetu-client">Desktop app</a>
</p>

<p align="center">
  <a href="https://github.com/nhridoy/shetu-server/releases/latest"><img alt="Latest release" src="https://img.shields.io/github/v/release/nhridoy/shetu-server"></a>
  <a href="LICENSE"><img alt="MIT license" src="https://img.shields.io/badge/license-MIT-8b7cff"></a>
  <img alt="Docker image" src="https://img.shields.io/badge/ghcr.io-shetu--server-5b8cff">
</p>

## What it does

- **Sign-in and accounts:** email and password with optional email verification over SMTP, refresh tokens, password change and recovery, and optional Google and GitHub OAuth. Login endpoints are rate limited.
- **Encrypted sync:** stores the desktop app's vault records and syncs them between devices. Sensitive fields (host addresses, usernames, passwords, private keys, commands) are encrypted on each device before they arrive; the server checks each record's shape, stores it and never decrypts it. Names, tags and timestamps stay readable so the server can sync them.
- **Teams:** create teams, invite people who already have an account, owner, admin and member roles, and shared vaults. Each shared vault has its own key, sealed to each member. Removing a member flags the team's vaults for a key rotation, which an owner or admin completes from the app with **Rotate keys**.

What the server can and cannot see is listed in the [security reference](https://shetu.iamnahid.com/docs/security#what-the-server-can-see). SSH traffic never passes through it: the desktop app connects to your hosts directly.

Built with Go, [Gin](https://gin-gonic.com) and [GORM](https://gorm.io). PostgreSQL in production; SQLite for local development.

## Run with Docker

Releases publish `ghcr.io/nhridoy/shetu-server` for `linux/amd64` and `linux/arm64`, plus Linux binaries on the [releases page](https://github.com/nhridoy/shetu-server/releases).

`docker-compose.prod.yml` only pulls the published image, so a host needs just that file and a `.env` made from `.env.example`:

```bash
curl -fsSLO https://raw.githubusercontent.com/nhridoy/shetu-server/main/docker-compose.prod.yml
curl -fsSL https://raw.githubusercontent.com/nhridoy/shetu-server/main/.env.example -o .env
# Set DATABASE_URL (PostgreSQL), JWT_SECRET and BASE_URL in .env.
# Generate a secret with: openssl rand -base64 48
# Optionally pin a release with SHETU_IMAGE_TAG=0.0.6 (default: latest).
docker compose -f docker-compose.prod.yml pull
docker compose -f docker-compose.prod.yml up -d
```

The container listens on 8080; `SHETU_HTTP_PORT` and `SHETU_BIND_IP` control the host side. Always put it behind a TLS-terminating reverse proxy such as Caddy, then set `BASE_URL` to the public HTTPS URL and `TRUSTED_PROXIES` to the proxy's address. **If the proxy runs on the same host, set `SHETU_BIND_IP=127.0.0.1`.** The default `0.0.0.0` publishes plain HTTP on every interface, where clients could bypass TLS and send credentials unencrypted. Otherwise, firewall port 8080 so only the proxy can reach it.

The [self-hosting guide](https://shetu.iamnahid.com/docs/server) has a full Compose file with PostgreSQL, the reverse proxy setup, OAuth, email verification and upgrades.

To build and run the image from this checkout instead:

```bash
docker compose up -d --build
```

## Configuration

Copy [`.env.example`](.env.example) to `.env`. It documents every variable. The ones you must set:

| Variable | Purpose |
|---|---|
| `DATABASE_URL` | `postgres://user:pass@host:5432/shetu?sslmode=require` in production (`sqlite://shetu.db` for development) |
| `JWT_SECRET` | Long random secret that signs access tokens |
| `BASE_URL` | Public URL of the server, used for OAuth callbacks |

Optional groups: Google and GitHub OAuth (`OAUTH_GOOGLE_*`, `OAUTH_GITHUB_*`), email verification (`REQUIRE_EMAIL_VERIFICATION`, `SMTP_*`), rate limits (`RATE_LIMIT_AUTH`, `RATE_LIMIT_API`), CORS and trusted proxies.

## Connect the desktop app

On Shetu's sign-in or sign-up screen, set **Server URL** to your server, for example `https://sync.example.com`, then create an account or sign in.

## Development

```bash
cp .env.example .env    # set JWT_SECRET; SQLite works locally
go run ./cmd/shetu-server
go test ./...
```

Releases are built by CI when a `v*` tag is pushed: tests run, Linux binaries are published and the multi-arch image is pushed to GHCR. Tags with a `-` (such as `v0.1.0-beta.1`) are prereleases.

## Roadmap

Planned work for the whole project, including the server, is in the [roadmap](https://github.com/nhridoy/shetu#roadmap).

## Related

- [shetu-client](https://github.com/nhridoy/shetu-client): the desktop SSH client
- [shetu](https://github.com/nhridoy/shetu): project home and issues
- [shetu-web](https://github.com/nhridoy/shetu-web): the website and docs

## License

[MIT](LICENSE)
