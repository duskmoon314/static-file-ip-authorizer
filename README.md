# static-file-ip-authorizer

A simple IP authorizer that works with caddy/nginx to allow/deny access to specified static files based on the client's
IP address, which is useful for datasets sharing.

## API

### `GET /auth`

- `X-Forwarded-For`: The client's IP address
- `X-Forwarded-URI`: The requested URI

Returns `200 OK` if the client's IP address is allowed to access the requested URI, otherwise returns `403 Forbidden`.
