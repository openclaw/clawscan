VERSION ?= dev
NPM_VERSION ?= $(if $(filter dev,$(VERSION)),v0.0.0-dev,$(VERSION))

.PHONY: release npm-package docs-site clean

release:
	./scripts/build-release.sh "$(VERSION)"

npm-package:
	node scripts/build-npm-package.mjs --version "$(NPM_VERSION)" --pack --smoke

docs-site:
	node scripts/build-docs-site.mjs

clean:
	rm -rf dist
