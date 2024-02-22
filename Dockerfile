FROM alpine:latest AS build

WORKDIR /build
COPY . .

RUN --mount=type=cache,target=/root/.rustup \
    --mount=type=cache,target=/root/.cache \
    --mount=type=cache,target=/var/cache/apk \
    --mount=type=cache,target=/build/target \
    set -eux; \
    apk update; \
    apk add binutils ca-certificates curl gcc musl-dev; \
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- --profile minimal -y; \
    source ~/.cargo/env; \
    cargo build --release; \
    cp target/release/fake-oauth /

FROM scratch

COPY ./assets/users.toml /var/lib/fake-oauth/users.toml
COPY --from=build /fake-oauth /fake-oauth
ENV FAKE_OAUTH_ADDR=0.0.0.0:7160
EXPOSE 7160
ENTRYPOINT ["/fake-oauth"]
