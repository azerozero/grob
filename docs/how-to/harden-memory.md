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
| `locked` | Linux | Adds `mlockall(MCL_CURRENT | MCL_FUTURE)` to `no-dump`. |

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
