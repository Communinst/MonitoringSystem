# Переменные
IMAGE_NAME := privatej0ker/dns-monitor:latest
NAMESPACE := kube-system
DS_NAME := dns-monitor
APP_LABEL := app=dns-monitor

.PHONY: build push config deploy restart logs dev clean

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

restart:
	@echo "==> Restarting DaemonSet..."
	kubectl rollout restart daemonset/$(DS_NAME) -n $(NAMESPACE)
	kubectl rollout status daemonset/$(DS_NAME) -n $(NAMESPACE) --timeout=10s || echo "Rollout timed out, but continuing..."


logs:
	@echo "==> Tailing logs with Stern..."
	stern -n $(NAMESPACE) -l $(APP_LABEL) --tail 50


dev: push deploy restart logs

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