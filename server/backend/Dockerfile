FROM rust:latest AS builder

WORKDIR /usr/src/app

COPY Cargo.lock .
COPY Cargo.toml .
COPY src/main.rs ./src/main.rs

RUN cargo build --release

FROM nginx:latest

WORKDIR /usr/src/app

COPY --from=builder /usr/src/app/target/release/secure-communicator-server /usr/src/app/secure-communicator-server
COPY nginx.conf /etc/nginx/nginx.conf
COPY start.sh /usr/src/app/start.sh

RUN touch messages.txt

ENV LISTENER=5005
ENV CLIENT=client-backend

EXPOSE 5004

RUN adduser --disabled-password appuser
RUN usermod -aG nginx appuser

RUN chmod +x start.sh
RUN touch /var/run/nginx.pid
RUN chown -R appuser:nginx /var/cache/nginx /usr/src/app /var/run/nginx.pid


USER appuser

ENTRYPOINT /usr/src/app/start.sh
