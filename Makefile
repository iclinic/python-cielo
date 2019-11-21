VERSION := $(shell python setup.py -q version)

clean:
	-find . -iname "*.py[ocd]" -delete
	-find . -iname "__pycache__" -exec rm -rf {} \;
	-rm -rf dist
	-rm -rf python_cielo.egg-info

build:
	python setup.py sdist

release: build
	git tag ${VERSION}
	git push origin ${VERSION}
	curl -F package=@dist/python-cielo-${VERSION}.tar.gz https://${GEMFURY_PUSH_TOKEN}@push.fury.io/iclinic/
