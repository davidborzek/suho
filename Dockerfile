# Build stage: rustables' build script runs bindgen, which needs libclang and
# the kernel UAPI headers (linux-libc-dev ships netfilter/nf_tables.h).
FROM rust:1-bookworm AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends clang libclang-dev linux-libc-dev \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN cargo build --release --locked
# Runtime: a distroless glibc image — no shell or package manager, just the
# binary. suho programs nftables over netlink (no `nft` binary, no libnftnl/
# libmnl); distroless/cc provides the glibc + libgcc_s the Rust binary needs.
FROM gcr.io/distroless/cc-debian12
COPY --from=build /src/target/release/suho /usr/local/bin/suho
ENTRYPOINT ["suho"]
