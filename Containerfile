# syntax=docker/dockerfile:1.7

FROM rust:1-alpine AS builder

WORKDIR /usr/src/static-file-ip-authorizer

RUN apk add --no-cache build-base pkgconf sqlite-dev

COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release --locked

FROM alpine:3 AS runtime

RUN apk add --no-cache ca-certificates sqlite-libs \
    && mkdir -p /var/lib/static-file-ip-authorizer

COPY --from=builder /usr/src/static-file-ip-authorizer/target/release/static-file-ip-authorizer /usr/local/bin/static-file-ip-authorizer

ENV XDG_DATA_HOME=/var/lib
EXPOSE 3000
VOLUME ["/var/lib/static-file-ip-authorizer"]

ENTRYPOINT ["static-file-ip-authorizer"]
