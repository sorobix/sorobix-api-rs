FROM rust:1.72
WORKDIR /sorobix-api-rs
COPY . .
RUN cargo build --release
RUN mv /sorobix-api-rs/target/release/sorobix-api-rs /sorobix-api-rs/server
EXPOSE 3000
CMD ["./server"]
