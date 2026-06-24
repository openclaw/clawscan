VERSION ?= dev

.PHONY: release npm-package docs-site clean

release:
	./scripts/build-release.sh "$(VERSION)"

npm-package:
	node scripts/build-npm-package.mjs --version "$(VERSION)" --pack --smoke

docs-site:
	node scripts/build-docs-site.mjs

clean:
	rm -rf dist
