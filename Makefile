.PHONY: install dev test clean help

install:  ## install production dependencies
	vendor/venv-update venv= -ppython3 .venv \
	install= -r requirements.txt

dev:  ## install development dependencies and pre-commit hooks
	vendor/venv-update venv= -ppython3 .venv \
	install= -r requirements.txt -r requirements-dev.txt
	.venv/bin/pre-commit install --install-hooks -f

test: dev  ## run unit tests
	# .venv/bin/python -m pytest \
	# --cov-report term-missing:skip-covered \
	# --cov=asrm/ \
	# tests/
	@echo
	.venv/bin/pre-commit install --install-hooks -f
	@echo
	.venv/bin/pre-commit run --all-files
	@echo
	.venv/bin/check-requirements

clean:  ## delete artifacts
	rm -f .coverage
	rm -rf .venv
	rm -rf .pytest_cache
	find . -type f -name '*.py[co]' -delete
	find . -type d -name '__pycache__' -delete

help:  ## display this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
