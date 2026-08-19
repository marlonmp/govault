test:
	@echo "downing runing containers"
	docker compose down
	docker compose -f compose.test.yml down -v
	@echo "starting test containers"
	docker compose -f compose.test.yml up -d
	@sleep 3
	@echo "seting up database"
	goose up
	@echo "runing tests"
	go test ./...
	@echo "cleaning up"
	docker compose -f compose.test.yml down -v

