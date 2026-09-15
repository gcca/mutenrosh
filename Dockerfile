FROM cgr.dev/chainguard/rust:latest-dev AS builder

USER root

RUN apk add --no-cache build-base binutils sqlite-dev

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN test -f /usr/lib/libsqlite3.a \
    && RUSTFLAGS='-C target-feature=+crt-static' cargo build --locked --release \
    && ! readelf -lW target/release/mutenroshi | grep -Fq 'Requesting program interpreter' \
    && ! readelf -dW target/release/mutenroshi | grep -Eq '\(NEEDED\)'

FROM cgr.dev/chainguard/static:latest

WORKDIR /app

COPY --from=builder --chown=nonroot:nonroot /app/target/release/mutenroshi /usr/local/bin/mutenroshi

USER nonroot

EXPOSE 8000

ENTRYPOINT ["/usr/local/bin/mutenroshi"]
