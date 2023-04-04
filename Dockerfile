FROM rust:1.68 as builder

WORKDIR /app
COPY . .
RUN cargo build --release


FROM rust:1.68
RUN rustup target add wasm32-unknown-unknown
RUN curl -LJO https://github.com/stellar/soroban-tools/releases/download/v0.6.0/soroban-cli-0.6.0-x86_64-unknown-linux-gnu
RUN mv soroban-cli-0.6.0-x86_64-unknown-linux-gnu soroban
RUN chmod +x soroban
RUN mv soroban /usr/local/bin
WORKDIR /app
COPY --from=builder /app/target/release/sorobix-api-rs .
EXPOSE 3000
CMD ["./sorobix-api-rs"]

