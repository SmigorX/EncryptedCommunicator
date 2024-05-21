FROM rust:latest AS builder

WORKDIR /usr/src/app

COPY ./Cargo.toml .
COPY ./Cargo.lock .

COPY ./src ./src

# Build the Rust application
RUN cargo build --release

FROM rust:slim

WORKDIR /usr/src/app

COPY --from=builder /usr/src/app/target/release/secure-communicator-client /usr/src/app/secure-communicator-client

ENTRYPOINT ["/usr/src/app/secure-communicator-client"]
