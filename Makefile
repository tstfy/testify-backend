.PHONY: env dev clean run kill help

env:
	python3 -m venv /home/testify/testify

dev:
	./dev.sh

clean:  ## delete artifacts
	rm -rf /home/testify/testify
	find . -type f -name '*.py[co]' -delete
	find . -type d -name '__pycache__' -delete

help:  ## display this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

run:
	./run.sh

kill:
	ps aux | grep flask | grep -v 5100 | awk '{print $$2}' | head -n2 | xargs sudo kill -9

routes:
	cat testifybackend/routes.py | grep app.route | cut -d '"' -f2,4
