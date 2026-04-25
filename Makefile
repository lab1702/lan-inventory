.PHONY: build test lint vet smoke clean

build:
	go build -o bin/lan-inventory ./cmd/lan-inventory

test:
	go test ./...

vet:
	go vet ./...

lint:
	go run honnef.co/go/tools/cmd/staticcheck@latest ./...

smoke: build
	sudo setcap cap_net_raw,cap_net_admin=eip ./bin/lan-inventory
	./bin/lan-inventory --once --table

clean:
	rm -rf bin/
