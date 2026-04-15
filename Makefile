# Переменные
IMAGE_NAME := privatej0ker/dns-monitor:latest
NAMESPACE := kube-system
DS_NAME := dns-monitor
APP_LABEL := app=dns-monitor

export KUBECONFIG := $(HOME)/.kube/config


# Компиляция BPF C-кода и генерация Go-обёрток через bpf2go.
# bpf2go сам вызывает clang с флагами из //go:generate директивы.
# Требуется clang на хосте. Пути в //go:generate относительные, поэтому cd.
.PHONY: bpf-generate install-tools build push config deploy restart logs dev clean

bpf-generate:
	@echo "==> Compiling BPF program and generating Go bindings..."
	cd internal/bpf && go generate

install-tools:
	@if command -v stern >/dev/null 2>&1; then \
		echo "==> stern is already installed. Skipping."; \
	else \
		echo "==> Installing stern..."; \
		wget -qO- https://github.com/stern/stern/releases/download/v1.30.0/stern_1.30.0_linux_amd64.tar.gz | tar xvz stern; \
		sudo mv stern /usr/local/bin/; \
		echo "==> stern installed successfully."; \
	fi

build:
	@echo "==> Building Docker image..."
	docker build -t $(IMAGE_NAME) .

push: build
	@echo "==> Pushing to Docker Hub..."
	docker push $(IMAGE_NAME)

config:
	@echo "==> Applying ConfigMaps..."
	kubectl create configmap dns-monitor-cfg-hook -n $(NAMESPACE) --from-env-file=cmd/hook_cfg.env --dry-run=client -o yaml | kubectl apply -f -
	kubectl create configmap dns-monitor-cfg -n $(NAMESPACE) --from-env-file=cmd/.env --dry-run=client -o yaml | kubectl apply -f -

deploy: config
	@echo "==> Applying DaemonSet and Monitoring..."
	kubectl apply -f daemonset.yaml
	kubectl apply -f monitoring.yaml
	helm upgrade prom-stack prometheus-community/kube-prometheus-stack -n monitoring -f prom-values.yaml

restart:
	@echo "==> Restarting DaemonSet..."
	kubectl rollout restart daemonset/$(DS_NAME) -n $(NAMESPACE)
	@# Fallback намеренный: rollout status ждёт ВСЕ ноды, включая NotReady/мёртвые.
	@# Если хотя бы один живой узел обновился — считаем перезапуск успешным.
	-kubectl rollout status daemonset/$(DS_NAME) -n $(NAMESPACE) --timeout=120s

wait-restart:
	@echo "==> Waiting for fresh DaemonSet rollout..."
	-kubectl rollout status daemonset/$(DS_NAME) -n $(NAMESPACE) --timeout=120s || true

logs:
	@echo "==> Tailing logs with Stern..."
	stern -n $(NAMESPACE) -l $(APP_LABEL) --tail 50


dev: push deploy restart logs
dev-force: push clean deploy restart logs
dev-test: push clean deploy wait-restart logs

# Полная очистка
clean:
	kubectl delete -f daemonset.yaml --ignore-not-found
	kubectl delete -f monitoring.yaml --ignore-not-found
	kubectl delete configmap dns-monitor-cfg-hook -n $(NAMESPACE) --ignore-not-found
	kubectl delete configmap dns-monitor-cfg -n $(NAMESPACE) --ignore-not-found
	@echo "==> Waiting 10 seconds for healthy pods to detach XDP hooks..."
	@sleep 10
	@echo "==> Forcibly cleaning up remaining ghost pods on dead nodes..."
	kubectl delete pods -l $(APP_LABEL) -n $(NAMESPACE) --force --grace-period=0 2>/dev/null || true