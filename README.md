<h1 align="center">Terra Server</h1>

<p align="center">
  The open-source sync server for <a href="https://terra.iamnahid.com">Terra</a>, the free SSH client and Termius alternative.<br>
  Run it yourself and keep accounts, encrypted vaults and team vaults on infrastructure you control.
</p>

<p align="center">
  <a href="https://terra.iamnahid.com/self-hosted">Overview</a> ·
  <a href="https://terra.iamnahid.com/docs/server">Self-hosting guide</a> ·
  <a href="https://terra.iamnahid.com/docs/security">Security reference</a> ·
  <a href="https://github.com/nhridoy/terra-client">Desktop app</a>
</p>

<p align="center">
  <a href="https://github.com/nhridoy/terra-server/releases/latest"><img alt="Latest release" src="https://img.shields.io/github/v/release/nhridoy/terra-server"></a>
  <a href="LICENSE"><img alt="MIT license" src="https://img.shields.io/badge/license-MIT-8b7cff"></a>
  <img alt="Docker image" src="https://img.shields.io/badge/ghcr.io-terra--server-5b8cff">
</p>

## What it does

- **Sign-in and accounts:** email and password with optional email verification over SMTP, refresh tokens, password change and recovery, and optional Google and GitHub OAuth. Login endpoints are rate limited.
- **Encrypted sync:** stores the desktop app's vault records and syncs them between devices. Records are encrypted on each device before they arrive; the server checks their shape and stores them, and never decrypts them.
- **Teams:** create teams, invite people who already have an account, owner, admin and member roles, and shared vaults. Each shared vault has its own key, sealed to each member and rotated when someone is removed.

What the server can and cannot see is listed in the [security reference](https://terra.iamnahid.com/docs/security#what-the-server-can-see). SSH traffic never passes through it: the desktop app connects to your hosts directly.

Built with Go, [Gin](https://gin-gonic.com) and [GORM](https://gorm.io). PostgreSQL in production; SQLite for local development.

## Run with Docker

Releases publish `ghcr.io/nhridoy/terra-server` for `linux/amd64` and `linux/arm64`, plus Linux binaries on the [releases page](https://github.com/nhridoy/terra-server/releases).

`docker-compose.prod.yml` is self-contained and only pulls the published image, so a host needs that file and a `.env`:

```bash
cp .env.example .env
# Set DATABASE_URL (PostgreSQL), JWT_SECRET and BASE_URL in .env.
# Generate a secret with: openssl rand -base64 48
# Optionally pin a release with TERRA_IMAGE_TAG=0.0.6 (default: latest).
docker compose -f docker-compose.prod.yml pull
docker compose -f docker-compose.prod.yml up -d
```

The container listens on 8080; `TERRA_HTTP_PORT` and `TERRA_BIND_IP` control the host side. Put it behind a TLS-terminating reverse proxy such as Caddy, then set `BASE_URL` to the public HTTPS URL and `TRUSTED_PROXIES` to the proxy's address.

The [self-hosting guide](https://terra.iamnahid.com/docs/server) has a full Compose file with PostgreSQL, the reverse proxy setup, OAuth, email verification and upgrades.

To build and run the image from this checkout instead:

```bash
docker compose up -d --build
```

## Configuration

Copy [`.env.example`](.env.example) to `.env`. It documents every variable. The ones you must set:

| Variable | Purpose |
|---|---|
| `DATABASE_URL` | `postgres://user:pass@host:5432/terra?sslmode=require` in production (`sqlite://terra.db` for development) |
| `JWT_SECRET` | Long random secret that signs access tokens |
| `BASE_URL` | Public URL of the server, used for OAuth callbacks |

Optional groups: Google and GitHub OAuth (`OAUTH_GOOGLE_*`, `OAUTH_GITHUB_*`), email verification (`REQUIRE_EMAIL_VERIFICATION`, `SMTP_*`), rate limits (`RATE_LIMIT_AUTH`, `RATE_LIMIT_API`), CORS and trusted proxies.

## Connect the desktop app

On Terra's sign-in or sign-up screen, set **Server URL** to your server, for example `https://sync.example.com`, then create an account or sign in.

## Development

```bash
cp .env.example .env    # set JWT_SECRET; SQLite works locally
go run ./cmd/terra-server
go test ./...
```

Releases are built by CI when a `v*` tag is pushed: tests run, Linux binaries are published and the multi-arch image is pushed to GHCR. Tags with a `-` (such as `v0.1.0-beta.1`) are prereleases.

## Related

- [terra-client](https://github.com/nhridoy/terra-client): the desktop SSH client
- [terra](https://github.com/nhridoy/terra): project home and issues
- [terra-web](https://github.com/nhridoy/terra-web): the website and docs

## License

[MIT](LICENSE)
