.PHONY: help build test clean run docker-build docker-run docker-up docker-down docker-logs

# Default target
help:
	@echo "Available targets:"
	@echo "  build        - Build the application"
	@echo "  test         - Run tests"
	@echo "  clean        - Clean build artifacts"
	@echo "  run          - Run the application locally"
	@echo "  docker-build - Build Docker image"
	@echo "  docker-run   - Run with Docker"
	@echo "  docker-up    - Start all services with docker-compose"
	@echo "  docker-down  - Stop all services"
	@echo "  docker-logs  - Show service logs"

# Build the application
build:
	./gradlew build

# Run tests
test:
	./gradlew test

# Clean build artifacts
clean:
	./gradlew clean

# Run the application locally
run:
	./gradlew bootRun

# Build Docker image
docker-build:
	docker build -t auth-service .

# Run with Docker
docker-run:
	docker run -p 8080:8080 --env-file .env auth-service

# Start all services
docker-up:
	docker-compose up -d

# Stop all services
docker-down:
	docker-compose down

# Show service logs
docker-logs:
	docker-compose logs -f