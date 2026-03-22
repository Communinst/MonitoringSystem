# Переменные
IMAGE_NAME := dns-monitor:local
NAMESPACE := kube-system
DS_NAME := dns-monitor
APP_LABEL := app=dns-monitor

.PHONY: build load config deploy restart logs dev clean

build:
	@echo "==> Building Docker image..."
	docker build -t $(IMAGE_NAME) .

load:
	@echo "==> Loading image into k3s..."
	docker save $(IMAGE_NAME) | sudo k3s ctr images import -

config:
	@echo "==> Applying ConfigMaps..."
	kubectl create configmap dns-monitor-cfg-hook -n $(NAMESPACE) --from-env-file=cmd/hook_cfg.env --dry-run=client -o yaml | kubectl apply -f -
	kubectl create configmap dns-monitor-cfg -n $(NAMESPACE) --from-env-file=cmd/.env --dry-run=client -o yaml | kubectl apply -f -

deploy: config
	@echo "==> Applying DaemonSet..."
	kubectl apply -f daemonset.yaml

# Перезапуск DaemonSet (нужно, чтобы k8s подхватил обновленный :local образ)
restart:
	@echo "==> Restarting DaemonSet..."
	kubectl rollout restart daemonset/$(DS_NAME) -n $(NAMESPACE)
	kubectl rollout status daemonset/$(DS_NAME) -n $(NAMESPACE)

logs:
	@echo "==> Tailing logs..."
	kubectl logs -f ds/$(DS_NAME) -n $(NAMESPACE)

# --- ГЛАВНАЯ КОМАНДА ДЛЯ РАЗРАБОТКИ ---
dev: build load config restart logs

# Полная очистка
clean:
	kubectl delete -f daemonset.yaml --ignore-not-found
	kubectl delete configmap dns-monitor-cfg-hook -n $(NAMESPACE) --ignore-not-found
	kubectl delete configmap dns-monitor-cfg -n $(NAMESPACE) --ignore-not-found