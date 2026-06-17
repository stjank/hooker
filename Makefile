.PHONY: build clean

build:
	python3 -m build

clean:
	rm -rf dist/ build/ *.egg-info
