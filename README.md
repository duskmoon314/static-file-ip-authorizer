# static-file-ip-authorizer

A small auth service for static-file gateways (Caddy/Nginx).

It decides whether a request is allowed based on:

1. Requested URI path (directory-prefix rules).
2. Client IP (`X-Forwarded-For`).
3. Rule mode:
   - `public = true` => allow.
   - `public = false` => allow only if client IP matches whitelist entries (IP or CIDR).

Default behavior is **deny** if no rule matches.

> Note: An empty database will cause no uri to be allowed, so make sure to add rules.

## Run

```bash
cargo run --release -- \
  --bind-addr 0.0.0.0:3000 \
  --log-filter info
```

CLI flags:

- `--bind-addr`: HTTP listen address (default `0.0.0.0:3000`)
- `--database-path`: SQLite DB path (default is the OS user data directory via the `directories` crate, such as `$XDG_DATA_HOME/static-file-ip-authorizer/static-file-ip-authorizer.db` or `$HOME/.local/share/static-file-ip-authorizer/static-file-ip-authorizer.db` on Linux)
- `--log-filter`: tracing filter (default `static_file_ip_authorizer=info,tower_http=info`)

## Container

The image listens on port `3000` and stores its SQLite database under
`/var/lib/static-file-ip-authorizer` by default through `XDG_DATA_HOME=/var/lib`.
Mount that directory as a persistent volume in production.

```bash
docker build -f Containerfile -t static-file-ip-authorizer:local .
docker run --rm -p 3000:3000 \
  -v static-file-ip-authorizer-data:/var/lib/static-file-ip-authorizer \
  static-file-ip-authorizer:local
```

To use a SQLite database file from the host, bind mount a host directory to the
container state directory:

```bash
mkdir -p ./data
touch ./data/static-file-ip-authorizer.db
docker run --rm -p 3000:3000 \
  -v "$PWD/data:/var/lib/static-file-ip-authorizer" \
  static-file-ip-authorizer:local
```

You can also mount a specific database file and pass its path explicitly:

```bash
mkdir -p ./data
touch ./data/rules.db
docker run --rm -p 3000:3000 \
  -v "$PWD/data/rules.db:/var/lib/static-file-ip-authorizer/rules.db" \
  static-file-ip-authorizer:local \
  --database-path /var/lib/static-file-ip-authorizer/rules.db
```

## API

### `GET /auth`

Headers:

- `X-Forwarded-For`: client IP (first value is used if comma-separated)
- `X-Forwarded-Uri`: requested URI path

Response:

- `200 OK`: allowed
- `403 Forbidden`: denied (or malformed/missing forwarded headers)

### `GET /rules`

Returns all rules in normalized JSON:

```json
{
  "rules": [
    {
      "dir": "/datasets/private",
      "public": false,
      "whitelist": ["10.0.0.0/8", "203.0.113.5"]
    }
  ]
}
```

### `PUT /rules/public`

Upsert/update a directory rule:

```bash
curl -sS -X PUT http://127.0.0.1:3000/rules/public \
  -H 'content-type: application/json' \
  -d '{"dir":"/datasets/private","public":false}'
```

### `POST /rules/whitelist`

Append whitelist entries (deduplicated and validated):

```bash
curl -sS -X POST http://127.0.0.1:3000/rules/whitelist \
  -H 'content-type: application/json' \
  -d '{"dir":"/datasets/private","entries":["10.0.0.0/8","203.0.113.5"]}'
```

## Notes

- Directory matching is recursive prefix matching (longest prefix wins).
- Whitelist entries support IPv4/IPv6 and CIDR.
- Existing SQLite DB files are supported on restart.
- This service is intended to run behind a trusted reverse proxy, not directly on the public internet.

## Integration

### Caddy

```caddyfile
:80 {
    forward_auth localhost:3000 {
        uri /auth

        header_up X-Forwarded-For {remote_host}
        header_up X-Forwarded-Uri {uri}
    }

    root * /path/to/static/files
    file_server browse
}
```
