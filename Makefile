.PHONY: install dev clean help

install:  ## install production dependencies
	vendor/venv-update venv= -ppython3 .venv \
	install= -r requirements.txt

dev:  ## install development dependencies
	pip3 install -r requirements.txt

clean:  ## delete artifacts
	rm -rf .venv
	rm -rf .pytest_cache
	find . -type f -name '*.py[co]' -delete
	find . -type d -name '__pycache__' -delete

help:  ## display this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
