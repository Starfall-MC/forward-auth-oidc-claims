tryit:
	RUST_LOG=debug cargo run --release -- -i ./secrets/client-id -s ./secrets/client-secret -u https://auth.starfallmc.space/realms/master --url http://127.0.0.1:8080 -k ./secrets/cookie-key -g -m email:X-User-Email -m discord_id:X-Discord-Id


all: build deploy

build:
	docker buildx build --platform linux/amd64 . --tag registry-starfallmc.danya02.ru/forward-auth-oidc:v1 --builder local --push


deploy:
	kubectl apply -f deploy-app.yaml

delete:
	kubectl delete -f deploy-app.yaml

redeploy:
	make build
	kubectl delete -f deploy-app.yaml; exit 0
	sleep 5
	kubectl apply  -f deploy-app.yaml


initialize_ns:
	kubectl create namespace buildkit

initialize_builder:
	docker buildx create --bootstrap --name=kube --driver=kubernetes --platform=linux/amd64 --node=builder-amd64 --driver-opt=namespace=buildkit,nodeselector="kubernetes.io/arch=amd64"
	docker buildx create --append --bootstrap --name=kube --driver=kubernetes --platform=linux/arm64 --node=builder-arm64 --driver-opt=namespace=buildkit,nodeselector="kubernetes.io/arch=arm64"

delete_builder:
	docker buildx rm kube