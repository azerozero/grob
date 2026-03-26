# CI/CD Pipeline PERT

## CI Workflow (push to develop / PR)

```mermaid
flowchart LR
  subgraph parallel["Parallel gates"]
    direction TB
    fmt["fmt\n~30s"]
    clippy["clippy x3 OS\n~3min"]
    audit["security audit\n~30s"]
    gitleaks["gitleaks\n~20s"]
    deny["cargo deny\n~30s"]
    docs["doc coverage\n~2min"]
    machete["unused deps\n~1min"]
    semver["semver check\n~2min"]
    feature["feature powerset\n~4min"]
    coverage["coverage\n~6min"]
  end

  subgraph testGate["Unit tests"]
    test["test x3 OS\n~5min"]
  end

  subgraph e2eGate["E2E pipeline"]
    direction TB
    musl["build musl binary\n~4min"]
    scratch["scratch container\n~10s"]
    pod["podman pod up\n~30s"]
    hurl["76 hurl tests\n~2min"]
    musl --> scratch --> pod --> hurl
  end

  subgraph loadGate["Load test"]
    load["k6 smoke\n~3min\n(manual only)"]
  end

  test --> e2eGate
  e2eGate --> load

  classDef critical fill:#E74C3C,stroke:#C0392B,color:#fff
  classDef gate fill:#4A90D9,stroke:#2C6CB0,color:#fff
  classDef manual fill:#F39C12,stroke:#D68910,color:#fff
  classDef par fill:#27AE60,stroke:#1E8449,color:#fff

  class fmt,clippy,audit,gitleaks,deny,docs,machete,semver,feature,coverage par
  class test gate
  class musl,scratch,pod,hurl critical
  class load manual
```

**Critical path**: test (5min) -> musl build (4min) -> container (10s) -> pod (30s) -> 76 tests (2min) = ~12min

## Release Workflow (tag push)

```mermaid
flowchart TB
  push["push develop"]
  releasePlz["release-plz\nbump + tag\n~1min"]
  push --> releasePlz

  releasePlz -->|"tag v*"| validate["validate version\n~10s"]

  validate --> build["cross build x4\nlinux-musl amd64/arm64\ndarwin x86/arm64\n~8min"]

  build --> container["crane push GHCR\nmulti-arch manifest\n~2min"]
  build --> release["GitHub Release\nbinaries + sha256\n~1min"]
  container --> release

  release --> homebrew["update Homebrew tap\n~30s"]
  homebrew --> brewTest["brew install test\nmacOS runner\n~2min"]

  classDef trigger fill:#4A90D9,stroke:#2C6CB0,color:#fff
  classDef critical fill:#E74C3C,stroke:#C0392B,color:#fff
  classDef publish fill:#27AE60,stroke:#1E8449,color:#fff

  class push,releasePlz trigger
  class validate,build critical
  class container,release,homebrew,brewTest publish
```

**Critical path**: validate (10s) -> cross build (8min) -> GHCR + Release -> Homebrew = ~14min

## Timing Summary

| Stage | Wall time | Trigger |
|-------|-----------|---------|
| CI parallel gates | ~6min | Every push |
| CI critical path (test -> e2e) | ~12min | Every push |
| Load test | +3min | Manual only |
| Release (tag -> GHCR + binaries) | ~14min | feat/fix commits on src/ |
