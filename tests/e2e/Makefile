# Grob E2E — one command to rule them all
# Usage:
#   make          # up + test + down
#   make up       # start pod (builds images if needed)
#   make test     # run all 69 hurl tests in container
#   make smoke    # 7 critical tests in <10s
#   make failover # Toxiproxy-orchestrated failover scenarios
#   make cb       # circuit-breaker lifecycle
#   make load     # k6 smoke load test
#   make down     # tear down pod
#   make clean    # down + remove images
#
# Everything runs inside containers. Only requirement: podman.

SHELL       := /bin/bash
E2E_DIR     := $(shell cd "$(dir $(lastword $(MAKEFILE_LIST)))" && pwd)
REPO_ROOT   := $(shell cd "$(E2E_DIR)/../.." && pwd)
POD_MANIFEST := $(E2E_DIR)/kube/e2e-pod.yml
HOST        := 127.0.0.1:13456
TOXI_API    := 127.0.0.1:8474
RUNNER_IMG  := localhost/e2e-runner:latest

# podman run inside the pod, mounting e2e tree
RUN = podman run --rm --pod e2e-pod -v $(E2E_DIR):/e2e:z $(RUNNER_IMG) -c

# All JWT variables, read from generated tokens on host (populated by init container)
define VARS
jwt_default=$$(cat /e2e/auth/tokens/jwt-default.txt) && \
jwt_expired=$$(cat /e2e/auth/tokens/jwt-expired.txt) && \
jwt_wrong_issuer=$$(cat /e2e/auth/tokens/jwt-wrong-issuer.txt) && \
jwt_wrong_audience=$$(cat /e2e/auth/tokens/jwt-wrong-audience.txt) && \
jwt_tampered=$$(cat /e2e/auth/tokens/jwt-tampered.txt) && \
jwt_self_signed=$$(cat /e2e/auth/tokens/jwt-self-signed.txt) && \
jwt_hospital_eu=$$(cat /e2e/auth/tokens/jwt-hospital-eu.txt) && \
jwt_team_perf=$$(cat /e2e/auth/tokens/jwt-team-perf.txt) && \
jwt_project_gdpr=$$(cat /e2e/auth/tokens/jwt-project-gdpr.txt) && \
jwt_algo_none=$$(cat /e2e/auth/tokens/jwt-algo-none.txt) && \
HURL_VARS="--variable host=$(HOST) \
  --variable jwt=$$jwt_default \
  --variable jwt_default=$$jwt_default \
  --variable jwt_expired=$$jwt_expired \
  --variable jwt_wrong_issuer=$$jwt_wrong_issuer \
  --variable jwt_wrong_audience=$$jwt_wrong_audience \
  --variable jwt_tampered=$$jwt_tampered \
  --variable jwt_self_signed=$$jwt_self_signed \
  --variable jwt_hospital_eu=$$jwt_hospital_eu \
  --variable jwt_team_perf=$$jwt_team_perf \
  --variable jwt_project_gdpr=$$jwt_project_gdpr \
  --variable jwt_algo_none=$$jwt_algo_none"
endef

# ─────────────────────────────────────────────────────────────────────────────
# Default: full cycle
# ─────────────────────────────────────────────────────────────────────────────
.PHONY: all
all: up wait-jwks init-proxies test down
	@echo ""
	@echo "======================================"
	@echo "  E2E cycle complete"
	@echo "======================================"

# ─────────────────────────────────────────────────────────────────────────────
# Infrastructure
# ─────────────────────────────────────────────────────────────────────────────
.PHONY: images
images:
	@echo "=== Building images ==="
	@podman image exists localhost/grob:e2e 2>/dev/null || \
		(echo "  pulling grob..." && podman pull ghcr.io/azerozero/grob:0.29.3 && \
		 podman tag ghcr.io/azerozero/grob:0.29.3 localhost/grob:e2e)
	@podman image exists localhost/vidaimock:e2e 2>/dev/null || \
		(echo "  building vidaimock..." && podman build -q -t localhost/vidaimock:e2e $(E2E_DIR)/images/vidaimock)
	@podman image exists $(RUNNER_IMG) 2>/dev/null || \
		(echo "  building runner..." && podman build -q -t $(RUNNER_IMG) $(E2E_DIR)/images/runner)
	@echo "  images ready"

.PHONY: up
up: images
	@echo ""
	@echo "=== Starting pod ==="
	@podman pod exists e2e-pod 2>/dev/null && podman pod rm -f e2e-pod >/dev/null 2>&1 || true
	@rm -rf $(E2E_DIR)/auth/keys $(E2E_DIR)/auth/tokens $(E2E_DIR)/auth/jwks.json $(E2E_DIR)/auth/nginx.conf
	@mkdir -p /tmp/grob-audit
	@export E2E_DIR=$(E2E_DIR) && envsubst '$${E2E_DIR}' < $(POD_MANIFEST) | podman play kube - >/dev/null
	@echo "  pod started"

.PHONY: wait-jwks
wait-jwks:
	@echo "  waiting for grob..."
	@for i in $$(seq 1 45); do \
		curl -sf http://$(HOST)/health >/dev/null 2>&1 && break; \
		sleep 1; \
	done
	@curl -sf http://$(HOST)/health >/dev/null 2>&1 || (echo "  FAIL: grob not healthy" && exit 1)
	@echo "  grob healthy"
	@echo "  waiting for JWKS..."
	@for i in $$(seq 1 15); do \
		curl -sf -X POST http://$(HOST)/api/config/reload >/dev/null 2>&1 || true; \
		sleep 2; \
		podman logs e2e-pod-grob 2>&1 | grep -q "Refreshed 1 JWKS" && break; \
	done
	@sleep 2
	@jwt=$$(cat $(E2E_DIR)/auth/tokens/jwt-default.txt 2>/dev/null || echo "missing"); \
	for i in $$(seq 1 5); do \
		curl -sf -X POST http://$(HOST)/v1/chat/completions \
			-H "Authorization: Bearer $$jwt" \
			-H "Content-Type: application/json" \
			-d '{"model":"default","messages":[{"role":"user","content":"ping"}],"max_tokens":5}' >/dev/null 2>&1 \
		&& break; \
		curl -sf -X POST http://$(HOST)/api/config/reload >/dev/null 2>&1 || true; \
		sleep 3; \
	done
	@echo "  JWT auth verified"

.PHONY: init-proxies
init-proxies:
	@bash $(E2E_DIR)/config/mock/init-proxies.sh 2>&1 | tail -1

.PHONY: down
down:
	@echo ""
	@echo "=== Stopping pod ==="
	@podman pod rm -f e2e-pod >/dev/null 2>&1 || true
	@echo "  pod removed"

.PHONY: clean
clean: down
	@echo "=== Cleaning images ==="
	@podman rmi -f localhost/grob:e2e localhost/vidaimock:e2e $(RUNNER_IMG) 2>/dev/null || true
	@rm -rf $(E2E_DIR)/auth/keys $(E2E_DIR)/auth/tokens $(E2E_DIR)/auth/jwks.json $(E2E_DIR)/auth/nginx.conf
	@echo "  clean"

# ─────────────────────────────────────────────────────────────────────────────
# Test suites
# ─────────────────────────────────────────────────────────────────────────────
.PHONY: test
test: test-hurl test-failover test-cb
	@echo ""
	@echo "======================================"
	@echo "  ALL SUITES PASSED"
	@echo "======================================"

.PHONY: test-hurl
test-hurl:
	@echo ""
	@echo "=== Hurl test suites ==="
	@$(RUN) ' \
		cd /e2e && \
		$(VARS) && \
		pass=0 && fail=0 && \
		for suite in happy fuzz secu auth budget cache policies negative pairwise; do \
			echo "" && \
			echo "--- $${suite} ---" && \
			if eval hurl --test --color $${HURL_VARS} tests/$${suite}/*.hurl; then \
				pass=$$((pass + 1)); \
			else \
				fail=$$((fail + 1)); \
			fi; \
		done && \
		echo "" && \
		echo "Suites: $${pass} passed, $${fail} failed" && \
		[ $${fail} -eq 0 ] \
	'

.PHONY: smoke
smoke:
	@echo ""
	@echo "=== Smoke (7 critical tests) ==="
	@$(RUN) ' \
		cd /e2e && \
		$(VARS) && \
		hurl --test --color $${HURL_VARS} \
			tests/happy/01-health.hurl \
			tests/happy/02-chat-simple.hurl \
			tests/auth/90-valid-jwt-succeeds.hurl \
			tests/auth/91-no-auth-header.hurl \
			tests/secu/30-no-key-in-errors.hurl \
			tests/negative/N0-jwt-self-signed.hurl \
			tests/fuzz/20-malformed-json.hurl \
	'

.PHONY: test-failover
test-failover:
	@echo ""
	@echo "=== Failover (Toxiproxy orchestrated) ==="
	@$(RUN) ' \
		cd /e2e && \
		jwt=$$(cat auth/tokens/jwt-default.txt) && \
		HOST=$(HOST) TOXIPROXY_API=http://$(TOXI_API) JWT=$$jwt \
			bash tests/failover/run-failover.sh \
	'

.PHONY: test-cb
test-cb:
	@echo ""
	@echo "=== Circuit Breaker (Toxiproxy orchestrated) ==="
	@$(RUN) ' \
		cd /e2e && \
		jwt=$$(cat auth/tokens/jwt-default.txt) && \
		HOST=$(HOST) TOXIPROXY_API=http://$(TOXI_API) JWT=$$jwt \
			bash tests/circuit-breaker/run-cb.sh \
	'

# Individual suites (for debugging)
.PHONY: test-happy test-fuzz test-secu test-auth test-budget test-cache test-policies test-negative test-pairwise
test-happy test-fuzz test-secu test-auth test-budget test-cache test-policies test-negative test-pairwise:
	@suite=$$(echo $@ | sed 's/test-//'); \
	echo ""; \
	echo "=== $${suite} ==="; \
	$(RUN) ' \
		cd /e2e && \
		$(VARS) && \
		hurl --test --color $${HURL_VARS} tests/'"$${suite}"'/*.hurl \
	'

# ─────────────────────────────────────────────────────────────────────────────
# Load tests
# ─────────────────────────────────────────────────────────────────────────────
.PHONY: load
load:
	@echo ""
	@echo "=== Load test (smoke: 10 VUs, 30s) ==="
	@$(RUN) ' \
		cd /e2e && \
		jwt=$$(cat auth/tokens/jwt-default.txt) && \
		k6 run --vus 10 --duration 30s load/smoke.js \
			-e HOST=$(HOST) -e JWT=$$jwt \
	'

.PHONY: load-stress
load-stress:
	@echo ""
	@echo "=== Load test (stress: ramp to 200 VUs) ==="
	@$(RUN) ' \
		cd /e2e && \
		jwt=$$(cat auth/tokens/jwt-default.txt) && \
		k6 run load/stress.js -e HOST=$(HOST) -e JWT=$$jwt \
	'

# ─────────────────────────────────────────────────────────────────────────────
# Help
# ─────────────────────────────────────────────────────────────────────────────
.PHONY: help
help:
	@echo "Grob E2E Test Suite"
	@echo ""
	@echo "  make              full cycle: up + test + down"
	@echo "  make up           start pod (builds images if needed)"
	@echo "  make test         run all suites (69 hurl + failover + CB)"
	@echo "  make smoke        7 critical tests in <10s"
	@echo "  make test-happy   run single suite (happy/fuzz/secu/auth/budget/cache/policies/negative/pairwise)"
	@echo "  make test-failover  Toxiproxy failover scenarios"
	@echo "  make test-cb      circuit-breaker lifecycle"
	@echo "  make load         k6 smoke load test (10 VUs, 30s)"
	@echo "  make load-stress  k6 stress test (ramp to 200 VUs)"
	@echo "  make down         stop pod"
	@echo "  make clean        stop pod + remove images"
	@echo ""
	@echo "Requirements: podman, envsubst, curl"
