FROM rust:slim as builder
RUN rustup toolchain install nightly
RUN rustup component add rust-src --toolchain nightly-x86_64-unknown-linux-gnu
COPY . . 
RUN RUSTFLAGS="-C target-feature=+crt-static -Zlocation-detail=none" \
  cargo +nightly build -Z build-std=std,panic_abort -Z build-std-features=panic_immediate_abort --target x86_64-unknown-linux-gnu --release
RUN rm -rf target/release && mv target/x86_64-unknown-linux-gnu/release target/release

FROM scratch
LABEL org.opencontainers.image.source=https://github.com/mmta/dsiem-esproxy
COPY --from=builder /target/release/dsiem-esproxy /
ENTRYPOINT [ "/dsiem-esproxy" ]