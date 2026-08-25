SHELL := /bin/bash
.DEFAULT_GOAL := help

# ------------------------------------------------------------------ build ---
.PHONY: build test test-race test-integration vet lint clean

build: ## Build all binaries into ./bin
	go build -o bin/gateway ./cmd/gateway
	go build -o bin/tollgate-admin ./cmd/tollgate-admin
	go build -o bin/upstream ./cmd/upstream

test: ## Unit tests
	go test ./...

test-race: ## Unit tests with the race detector
	go test -race ./...

test-integration: ## Integration tests (needs the compose stack: make up)
	TOLLGATE_TEST_REDIS=localhost:6379 go test -count=1 ./internal/ratelimit/ -run TestRedis -v

vet:
	go vet ./...

clean:
	rm -rf bin loadtest/results

# ------------------------------------------------------------- local dev ---
.PHONY: up down seed logs demo-hot-reload

up: ## Start the local compose stack
	docker compose up -d --build
	@echo "gateway:    http://localhost:8080"
	@echo "console:    http://localhost:8080/_admin/  (token: $${ADMIN_TOKEN:-local-dev-admin-token-change-me})"
	@echo "admin:      http://localhost:9090/metrics"
	@echo "prometheus: http://localhost:9091"
	@echo "jaeger:     http://localhost:16686"

down:
	docker compose down -v

seed: ## Migrate + seed demo tenants; prints API key exports
	scripts/seed.sh compose

logs:
	docker compose logs -f gateway

# ------------------------------------------------------------------ kind ---
.PHONY: kind-up kind-down docker-build kind-load tf-apply tf-destroy \
        monitoring-install helm-install helm-install-memory kind-seed deploy

kind-up: ## Create the kind cluster
	kind create cluster --config deploy/kind/cluster.yaml --name tollgate || true

kind-down:
	kind delete cluster --name tollgate

docker-build: ## Build gateway + upstream images
	docker build --target gateway  -t tollgate:dev .
	docker build --target upstream -t tollgate-upstream:dev .

kind-load: docker-build ## Load images into kind
	kind load docker-image tollgate:dev --name tollgate
	kind load docker-image tollgate-upstream:dev --name tollgate

tf-apply: ## Terraform: Redis + Postgres into the cluster
	terraform -chdir=deploy/terraform init -input=false
	terraform -chdir=deploy/terraform apply -auto-approve

tf-destroy:
	terraform -chdir=deploy/terraform destroy -auto-approve

monitoring-install: ## Prometheus + prometheus-adapter (for the p99 HPA)
	helm repo add prometheus-community https://prometheus-community.github.io/helm-charts >/dev/null 2>&1 || true
	helm repo update >/dev/null
	helm upgrade --install prometheus prometheus-community/prometheus \
	  -n monitoring --create-namespace -f deploy/monitoring/prometheus-values.yaml
	helm upgrade --install prometheus-adapter prometheus-community/prometheus-adapter \
	  -n monitoring -f deploy/monitoring/adapter-values.yaml

helm-install: ## Deploy the gateway (3 replicas, redis limiter)
	helm upgrade --install tollgate deploy/helm/tollgate -n tollgate --create-namespace \
	  --set limiter=redis

helm-install-memory: ## Deploy with the NAIVE per-replica limiter (for the demo)
	helm upgrade --install tollgate deploy/helm/tollgate -n tollgate --create-namespace \
	  --set limiter=memory

kind-seed: ## Migrate + seed inside the kind cluster
	scripts/seed.sh kind

deploy: kind-up kind-load tf-apply monitoring-install helm-install ## Full kind deployment

# ------------------------------------------------------------- load tests ---
.PHONY: k6-baseline k6-correctness k6-fairness bench bench-limiter-cost \
	bench-limiter-cost-local bench-limiter-cost-incluster

bench-limiter-cost: bench-limiter-cost-local bench-limiter-cost-incluster ## Run the matched local and EKS limiter-cost protocol
	python3 bench/compare.py bench/results/local bench/results/incluster \
	  bench/results/limiter_cost_comparison.json > bench/results/limiter_cost_comparison.txt

bench-limiter-cost-local: ## Run the matched limiter-cost protocol in Docker Compose
	bench/run-local.sh

bench-limiter-cost-incluster: ## Run the matched limiter-cost protocol in the current Kubernetes context
	bench/run-incluster.sh

k6-baseline: ## Latency/throughput at three load levels
	scripts/run-k6.sh baseline

k6-correctness: ## Distributed rate limit correctness across replicas
	scripts/run-k6.sh correctness

k6-fairness: ## Noisy tenant cannot starve a quiet one
	scripts/run-k6.sh fairness

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'
