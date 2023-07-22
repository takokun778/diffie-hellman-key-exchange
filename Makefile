.PHONY: back
back:
	@go run cmd/backend/main.go

.PHONY: front
front:
	@go run cmd/frontend/main.go
