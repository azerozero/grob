# E2E Test Suite -- Entry and Exit Criteria

## Entry Criteria

All of the following must be true before any test execution begins:

1. **Pod healthy**: `just up` completes without error; the Grob container
   reports healthy via `/healthz` (HTTP 200).
2. **Mock services responding**: VidaiMock on port 8100 and Toxiproxy API on
   port 8474 both accept connections.
3. **JWKS loaded**: The mock-jwks nginx container on port 8443 serves the
   `.well-known/jwks.json` endpoint and Grob has fetched it (verified by a
   successful JWT-authenticated request).
4. **Auth fixtures generated**: `just generate-auth` has been run; all token
   files in `auth/tokens/` are present and non-empty.
5. **Toxiproxy proxies initialized**: anthropic-mock (9001), openai-mock (9002),
   and gemini-mock (9003) are registered and forwarding to VidaiMock.

## Exit Criteria

### Smoke Suite (`just test-smoke`)

- **Pass rate**: 100% (all tests must pass).
- **Duration**: under 10 seconds wall-clock time.
- **Blocking**: a smoke failure blocks further test execution in CI.

### Full Suite (`just test`)

- **Pass rate**: 95% or higher (at most 3 failures out of ~60 tests).
- **Security tests**: 100% pass required for all tests in `tests/negative/`
  and `tests/secu/`. Any security failure is a release blocker regardless of
  overall pass rate.
- **Duration**: under 60 seconds wall-clock time (mock-backed suite only;
  excludes live and load tests).

### Live Tests (`just test-live-*`)

- Informational only; failures do not block release.
- Skipped automatically when API keys are not set.

## Coverage Threshold

- Every feature listed in `RTM.md` must be covered by at least one test file.
- New features must add an RTM row and corresponding test before merge.

## Performance Targets

| Suite | Target |
|-------|--------|
| Smoke (`test-smoke`) | < 10 s |
| Full mock suite (`test`) | < 60 s |
| Load smoke (`load-smoke`) | p95 < 200 ms, 0 errors |
