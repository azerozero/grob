# Harden process memory

Use named encrypted credentials, a dedicated OS account, and a foreground Grob
process supervised by your service manager. Keep `adopt_from_system = false`
for credentials you manage explicitly. Apply the memory policy before startup:

```sh
GROB_MEMORY_HARDENING=no-dump grob run
```

| Mode | Platforms | Effect |
|------|-----------|--------|
| `off` or unset | All | Keeps the operating system's existing policy. |
| `no-dump` | Unix | Sets both core-file limits to zero; Linux also sets `PR_SET_DUMPABLE=0`. |
| `locked` | Linux | Adds `mlockall` for current and future mappings to `no-dump`. |

Grob applies these controls before it creates the Tokio runtime, loads config or
reads credentials. Invalid modes, unsupported platforms, and failed system calls
stop startup. An explicitly requested mode never silently falls back to `off`.
Windows operators must use host policy for crash dumps and memory protection.

## Prevent swapping on a Linux service

Configure the service's memlock allowance for peak **virtual memory**, including
runtime stacks, HTTP buffers and allocator reservations. For a dedicated,
capacity-controlled host, a systemd override can contain:

```ini
[Service]
Environment=GROB_MEMORY_HARDENING=locked
LimitCORE=0
LimitMEMLOCK=infinity
NoNewPrivileges=true
```

Run Grob as an unprivileged account. A suitable service-manager limit avoids
granting the daemon root access just to lock memory. Set a separate memory/cgroup
budget appropriate to the workload. Validate the mode under your expected peak
load before enabling it in production: insufficient locked-memory allowance can
make later allocations or stack growth fail. Inspect `VmLck` in
`/proc/<grob-pid>/status` from an authorized host account.

Prefer `grob run` under the supervisor. Lock settings do not survive `exec`, and
Grob applies them again in each new Grob process. Core resource limits also affect
child commands launched by `grob exec`; do not enable this mode on a development
launcher if those commands need core dumps.

Disable hibernation and host/kernel crash dumps where your operating policy
requires it. Use encrypted volumes and encrypted swap, or disable swap at the host
level. Process locking does not prevent a hibernation image or host snapshot from
capturing RAM. These settings require host administration; Grob does not change
them.

The Linux documentation describes [memory locking and its resource limits](https://man7.org/linux/man-pages/man2/mlock.2.html)
and [dumpability and ptrace restrictions](https://man7.org/linux/man-pages/man2/PR_SET_DUMPABLE.2const.html).
The [libsodium memory guidance](https://doc.libsodium.org/memory_management)
also distinguishes zeroing, locking, guarded allocation and host-level controls.

## Encrypt memory with a hardware trust boundary

Deploy on a supported confidential VM when the threat model includes host or
hypervisor inspection. [AMD SEV-SNP](https://www.amd.com/en/developer/sev.html)
is one hardware-backed option. Validate current platform firmware, guest images,
the attestation chain and an external key-release policy with your infrastructure
operator. Merely detecting a TEE device is insufficient to trust a workload.

Grob's current `tee.mode = "enforce"` checks that a supported TEE is detected.
Its optional attestation reporting does not independently verify the certificate
chain, workload identity, freshness or an external verifier's policy. Do not use
that setting alone as proof of confidential deployment.

Encrypting an idle buffer with a key in the same process cannot protect against
arbitrary execution in that process. Grob uses established AES-GCM at rest and
zeroizing secret containers, rather than adding another in-process crypto layer.
The memory modes reduce exposure through ordinary dumps and swap; they cannot
protect against a compromised guest kernel, root with inspection capabilities,
malicious code inside Grob, or a provider receiving the authorized plaintext.

## Security assurance scope

These controls provide technical hardening. They are not NATO certification or
approval to process classified information. NATO's
[NIAPC vendor guidance](https://www.ia.nato.int/niapc/Information/NIAPC-vendor-info)
describes national evaluation and approval requirements for cryptographic
products. No such evaluation or accreditation is claimed for Grob.

## Reproduce the checks

Use temporary stores and synthetic credentials; no real provider is required:

```sh
cargo test --lib storage::process_tests -- --nocapture
cargo test --lib security::memory::tests -- --nocapture
cargo test --release --lib credential_load -- --ignored --nocapture
```

The process tests kill child processes at atomic-write, rotation, refresh and
journal boundaries. A published encrypted credential is old or new and still
authenticated. A revoked key is never reactivated. Rotation interrupted before
revocation can leave an unused replacement record whose secret was never returned;
inspect and revoke that record before retrying a manual rotation.

A flushed spend event survives a process kill. An event interrupted before its
append is absent; a torn journal prevents startup instead of resetting the
budget. Spend uses batched fsync, so process-kill tests do not prove zero loss
during power failure. Provider charges for interrupted requests may also require
reconciliation. Filesystem and hardware power-loss tests remain a deployment
responsibility.

Streaming completion, upstream failure and client cancellation each record the
usage observed so far exactly once. The graceful-shutdown counter includes
streaming bodies and their accounting tasks; journals are flushed after draining.
If draining exceeds its 30-second deadline or the process is killed, outstanding
work may still be lost. A local usage count cannot account for provider work
performed after the client disconnects and never reported to Grob.

The load test runs the real HTTP router with a local backend, a stable virtual
agent key, cache disabled, and literal versus live encrypted credentials in ABBA
order. It measures latency from scheduled arrival through response body, including
queue delay, at 100, 500 and 1,000 offered requests per second. It also replaces the
upstream secret under load and checks that no old credential is used after
in-flight requests drain. Set `GROB_LOAD_REPORT` to save its JSON results. This
local probe is not a capacity guarantee for remote providers or a confidential VM.

## Run Linux qualification in CI

The `Memory and crash recovery` workflow runs on ephemeral Ubuntu 24.04 runners.
The main CI calls it for Rust, dependency, workflow, `scripts/ci/` and container-build changes;
`Required checks` blocks merging if qualification fails or is cancelled.
Documentation-only changes skip it. It can also be launched manually with a
`memlock_mib` limit between 64 and 1,024 MiB.

The memory test builds the release binary with the normal allocator, drops root
privileges before execution, and starts Grob with `GROB_MEMORY_HARDENING=locked`.
It checks startup rejection at zero allowance, then runs 3,000 real HTTP requests
with 64 KiB inputs and concurrency 1, 16 and 64. The default memlock limit is
512 MiB; address space is capped at 2 GiB. Samples of `/proc/<pid>/status` must show
locked pages, no swap, the expected unprivileged UID and no effective capabilities.
Any HTTP failure or failed graceful shutdown fails the job. This is a bounded
functional stress test, not a throughput or latency SLO.

The recovery test boots a separate Linux kernel with an ext4 scratch disk in QEMU.
At each credential-write, rotation, deletion, refresh-intent or journal checkpoint,
the runner kills **QEMU itself** with SIGKILL. It restarts a new guest against the
same disk and checks authenticated credentials, revocation, durable spend and
refusal to open corrupt accounting. The test binary contains the pause hooks;
the shipped Grob binary does not. No real credentials or host block devices are used.

QEMU uses `cache=writeback`, with flushes enabled; `cache=unsafe` and `-snapshot`
would weaken the test. See the [QEMU cache documentation](https://www.qemu.org/docs/master/system/invocation.html).
This loses guest RAM and the guest kernel's page cache, including state that a
process-only kill would preserve. The host cache and physical disk remain powered.
It does **not** validate drive firmware, volatile controller caches, power-loss
protection or the physical server's storage stack.

Download the `hardening-<commit>` artifact for `memory.json`, actual process limits,
Grob logs, guest serial logs and `recovery.json`. A missing checkpoint, VM boot
failure, timeout or failed recovery assertion fails qualification; there is no
silent fallback to a process-only test. Reproduce a failure on a disposable runner
using the same commit, kernel, limit and filesystem before changing the assertions.

To qualify a deployment, repeat with its kernel, allocator, service limits,
filesystem and peak workload. Hosted CI supplies a repeatable Linux reference
environment; it does not establish equivalence to an unspecified target server.

## Crash and recreate the production container

The same required workflow builds the root `Containerfile` from the commit under
test and runs `scripts/ci/container-recovery.py`. The Python standard-library driver
uses Docker in CI and also supports Podman; it requires no Go toolchain or Python
packages. To reproduce locally:

```sh
podman build --platform linux/amd64 -f Containerfile -t localhost/grob:crash-test .
python3 scripts/ci/container-recovery.py --engine podman \
  --image localhost/grob:crash-test --output /tmp/grob-container-recovery
```

The root build targets Linux amd64. Use an amd64 builder or configured emulation
when building from another architecture. The driver can also test a matching
released image, but CI always builds the source revision being reviewed.

Grob runs as UID/GID 65534 with a read-only root filesystem, no capabilities,
`no-new-privileges`, a 512 MiB memory limit, a 64-process limit, zero core allowance
and `GROB_MEMORY_HARDENING=no-dump`. A named volume contains `GROB_HOME`; `/tmp`
is a bounded tmpfs. The synthetic provider initializes that disposable volume,
drops root before serving, and verifies the upstream credential. Only ephemeral
loopback ports are published. The two containers share a network namespace so
synthetic HTTP stays on loopback without relaxing Grob's HTTPS credential policy.
No host credential directory is mounted.

Each of three cycles completes 128 concurrent HTTP requests, creates and rotates
virtual keys, and revokes another key. Eight more requests are held inside the mock
provider before any usage is returned. The driver sends
[`SIGKILL`](https://docs.docker.com/reference/cli/docker/container/kill/), requires
exit 137 without OOM, removes the container and starts a new one on the same volume.
It checks exact spend and request-count recovery, unchanged key records, active-key
authentication, revoked-key rejection and interruption of all held requests.
A separate SIGTERM/recreate check validates graceful shutdown. Finally a partial
journal record is injected while Grob is stopped: startup must fail with the
unreadable-journal diagnostic instead of resetting the budget.

Download `container-recovery-<commit>` for the JSON report, per-container logs and
inspection records. Cleanup removes only the test's UUID-named containers, volume
and network, including after failures. All credentials are synthetic. Interrupted
requests have no reported usage; this does not assert that a real provider would
waive charges for work already performed.

A container kill preserves the host kernel and its page cache. This complements
the whole-VM cut test above; neither test simulates loss of power to a physical SSD.
