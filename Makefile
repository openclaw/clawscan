VERSION ?= dev

.PHONY: release docs-site clean

release:
	./scripts/build-release.sh "$(VERSION)"

docs-site:
	node scripts/build-docs-site.mjs

clean:
	rm -rf dist
