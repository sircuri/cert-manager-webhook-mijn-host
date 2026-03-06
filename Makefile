IMAGE_NAME ?= cert-manager-webhook-mijn-host
IMAGE_TAG ?= latest

.PHONY: build test clean docker-build

build:
	go build -o webhook .

test:
	go test ./...

clean:
	rm -f webhook

docker-build:
	docker build -t $(IMAGE_NAME):$(IMAGE_TAG) .
