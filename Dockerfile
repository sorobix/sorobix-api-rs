FROM rust:1.68
RUN rustup target add wasm32-unknown-unknown
RUN curl -LJO https://github.com/stellar/soroban-tools/releases/download/v0.6.0/soroban-cli-0.6.0-x86_64-unknown-linux-gnu
RUN mv soroban-cli-0.6.0-x86_64-unknown-linux-gnu soroban
RUN chmod +x soroban
RUN mv soroban /usr/local/bin
RUN curl -LJO https://github.com/mozilla/sccache/releases/download/v0.4.1/sccache-v0.4.1-x86_64-unknown-linux-musl.tar.gz
RUN tar -xvf sccache-v0.4.1-x86_64-unknown-linux-musl.tar.gz
RUN mv sccache-v0.4.1-x86_64-unknown-linux-musl/sccache /usr/local/bin
ENV RUSTC_WRAPPER=/usr/local/bin/sccache
WORKDIR /sorobix-api-rs
COPY . .
RUN cargo build --release
RUN mv /sorobix-api-rs/target/release/sorobix-api-rs /sorobix-api-rs/server
EXPOSE 3000
CMD ["./server"]
