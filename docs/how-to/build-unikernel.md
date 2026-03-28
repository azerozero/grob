# How to Build a Grob Unikernel Image

Build a minimal grob binary for unikernel deployment (Unikraft, Firecracker,
Cloud Hypervisor) or ultra-lightweight scratch containers.

## Prerequisites

- Rust toolchain with `x86_64-unknown-linux-musl` target
- Docker (for container-based builds)
- [KraftKit](https://github.com/unikraft/kraftkit) (for native Unikraft images)

```bash
rustup target add x86_64-unknown-linux-musl
```

## Option 1: Docker Multi-Stage Build

Produces a scratch container (~15 MB) with just the static binary and CA certs.

```bash
docker build -f Dockerfile.unikernel -t grob:unikernel .
docker run --rm -p 8080:8080 \
  -v ./grob.toml:/etc/grob/grob.toml \
  grob:unikernel
```

### Extract the Binary

To use the binary in a Unikraft rootfs or Firecracker setup:

```bash
CONTAINER=$(docker create grob:unikernel)
docker cp "$CONTAINER":/grob ./rootfs/grob
docker rm "$CONTAINER"
```

## Option 2: Native Cargo Build

```bash
cargo build --release \
  --no-default-features \
  --features "dlp,oauth,tap,compliance,mcp,policies,unikernel" \
  --target x86_64-unknown-linux-musl
```

The binary is at `target/x86_64-unknown-linux-musl/release/grob`.

## Option 3: Unikraft via KraftKit

```bash
kraft build
kraft run -p 8080:8080
```

The `kraft.yaml` at the repository root configures the Unikraft build with
`LIBPOSIX_EVENT` (required by tokio) and the lwIP network stack.

## What the `unikernel` Feature Changes

The `unikernel` feature flag disables platform-specific dependencies that are
unavailable or unnecessary in a unikernel environment:

| Dependency | Default | Unikernel | Reason |
|---|---|---|---|
| `tikv-jemallocator` | enabled | disabled | Unikraft provides its own allocator |
| `nix` (signals) | enabled | disabled | No POSIX signals in most unikernels |
| `socket2` | enabled | disabled | No `SO_REUSEPORT` in unikernel stacks |
| `dirs` | enabled | disabled | No home directory concept |

Set `GROB_HOME=/etc/grob` to configure the data directory explicitly.

## Configuration

Unikernel deployments require explicit paths since `~/.grob` resolution is
disabled. Provide configuration via:

1. **Environment variable**: `GROB_HOME=/etc/grob`
2. **CLI flag**: `grob start --config /etc/grob/grob.toml`
3. **Mount**: Bind-mount the config file into the rootfs or container

## Size Budget

The unikernel binary must stay under **20 MB** (enforced in CI). Typical sizes:

| Build | Approximate Size |
|---|---|
| Default (with jemalloc) | ~17 MB |
| Unikernel (musl malloc) | ~14 MB |

## Allocator Performance: jemalloc vs musl malloc

> **Placeholder** — fill in after running production benchmarks.

Expected trade-offs:

- **jemalloc**: ~20% better throughput under high concurrency due to
  thread-local caching and reduced lock contention.
- **musl malloc**: Smaller binary, simpler memory model, adequate for
  single-vCPU unikernel deployments with moderate concurrency.

Benchmarks to run:

```bash
# Default build (jemalloc)
cargo bench --bench hotpath

# Unikernel build (musl malloc)
cargo bench --bench hotpath --no-default-features \
  --features "dlp,oauth,tap,compliance,mcp,policies,unikernel"
```

Compare p50/p99 latency and throughput under `wrk` load testing with varying
connection counts (1, 10, 100, 500).
