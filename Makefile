SHELL=/bin/bash
export REPO=rest-ws

.PHONY: run-local
run_local:
	@docker compose up -d db_dev_rest_api;
	@go run main.go;


