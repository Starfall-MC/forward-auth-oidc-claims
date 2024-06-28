FROM rust:latest AS builder

ENV HOME=/home/root

WORKDIR $HOME/app

RUN rustup default nightly

ADD src src
ADD Cargo.lock .
ADD Cargo.toml .

RUN --mount=type=cache,target=/usr/local/cargo/registry \
	--mount=type=cache,target=/home/root/app/target \
	cargo build --release && mv target/release/forward-auth-oidc-claims .



FROM debian:stable-slim
RUN apt-get update && apt-get install -y libssl3 ca-certificates && apt-get clean && rm -rf /var/lib/apt/lists/*

COPY --from=builder /home/root/app/forward-auth-oidc-claims .

CMD ["./forward-auth-oidc-claims"]