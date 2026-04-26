.PHONY: build test lint vet smoke clean manuf-refresh

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

manuf-refresh:
	@echo "Fetching Wireshark manuf database..."
	@curl -sSfL https://www.wireshark.org/download/automated/data/manuf -o /tmp/manuf.raw
	@echo "Filtering to 24-bit OUI entries..."
	@grep -v '^#' /tmp/manuf.raw | grep -v '^$$' | grep -v '/' > internal/oui/manuf.txt
	@rm -f /tmp/manuf.raw
	@wc -l internal/oui/manuf.txt
	@echo "Done. Review the diff and commit if it looks right."
