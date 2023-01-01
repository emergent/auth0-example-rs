FROM rust:1-buster AS builder
WORKDIR /build/

COPY Cargo.toml Cargo.lock /build/
RUN mkdir /build/src
RUN echo 'fn main(){println!("empty")}' > /build/src/main.rs
RUN cargo build --release
RUN rm -rf /build/src

COPY src /build/src
COPY templates /build/templates
COPY static /build/static
RUN cargo build --release


FROM debian:buster-slim
RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*
ENV SSL_CERT_DIR=/etc/ssl/certs

WORKDIR /work/
COPY --from=builder /build/target/release/auth0-example-rs /work/
COPY --from=builder /build/templates /work/templates
COPY --from=builder /build/static /work/static
COPY .env /work/.env

EXPOSE 3000
ENTRYPOINT [ "/work/auth0-example-rs" ]
