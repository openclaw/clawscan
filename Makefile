VERSION ?= dev

.PHONY: release clean

release:
	./scripts/build-release.sh "$(VERSION)"

clean:
	rm -rf dist
