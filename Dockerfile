FROM rust:1.75-slim AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock* ./
COPY src ./src
RUN cargo build --release

FROM debian:bookworm-slim
WORKDIR /app
COPY --from=builder /build/target/release/rustchef /usr/local/bin/rustchef
COPY samples ./samples
ENTRYPOINT ["rustchef"]
CMD ["--help"]
