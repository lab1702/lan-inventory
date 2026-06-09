.PHONY: build test lint vet smoke clean manuf-refresh

# Windows users: run `go build ./cmd/lan-inventory` directly — the setcap
# step does not apply. Npcap install handles capture privilege at install
# time.
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
	@echo "Stripping comments and blank lines..."
	@# Keep every allocation: MA-L (/24), MA-M (/28) and MA-S (/36). The parser
	@# does longest-prefix matching across all three widths, so we no longer
	@# filter slash-masked rows. (We must not grep out '/' wholesale anyway:
	@# ~289 /24 vendor names legitimately contain a slash, e.g. "... A/S".)
	@grep -v '^#' /tmp/manuf.raw | grep -v '^$$' > internal/oui/manuf.txt
	@rm -f /tmp/manuf.raw
	@wc -l internal/oui/manuf.txt
	@echo "Done. Review the diff and commit if it looks right."
