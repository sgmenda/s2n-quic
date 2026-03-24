FROM rust:1.88 AS builder
WORKDIR /src
COPY . .
RUN cargo build --release -p s2n-quic-mtc --bin twig

FROM debian:bookworm-slim
RUN apt-get update && \
    apt-get install -y ca-certificates caddy && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/target/release/twig /usr/local/bin/twig
COPY quic/s2n-quic-mtc/deploy/Caddyfile /etc/caddy/Caddyfile
COPY quic/s2n-quic-mtc/deploy/start.sh /start.sh
RUN chmod +x /start.sh

VOLUME /data
EXPOSE 80 443

CMD ["/start.sh"]
