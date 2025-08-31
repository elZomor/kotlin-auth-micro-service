# Authentication Service

A clean, modern authentication and authorization service built with Kotlin, Spring Boot, and JWT tokens.

## 🏗️ Project Structure

This project follows clean architecture principles with clear separation of concerns:

```
src/main/kotlin/com/auth/
├── AuthApplication.kt              # Main application entry point
├── common/                         # Shared utilities and constants
│   └── BcryptTest.kt              # Password hashing utilities
├── domain/                         # Core business logic
│   ├── model/                     # Domain entities
│   ├── repository/                # Repository interfaces  
│   └── service/                   # Domain services
├── infrastructure/                # External concerns
│   ├── persistence/               # Database implementations
│   ├── security/                  # Security configurations and services
│   └── config/                    # Spring configurations
└── presentation/                  # Web layer
    ├── controller/                # REST controllers
    ├── dto/                      # Data transfer objects
    └── filter/                   # Web filters
```

## 🚀 Features

- **JWT Authentication**: Secure token-based authentication with refresh tokens
- **Role-Based Access Control (RBAC)**: Fine-grained permissions system
- **Password Security**: BCrypt hashing with configurable strength
- **Token Blacklisting**: Secure logout and token invalidation
- **Input Validation**: Comprehensive request validation
- **Clean Architecture**: Well-organized, maintainable codebase
- **Comprehensive Testing**: 90%+ test coverage with unit and integration tests
- **CI/CD Pipeline**: Automated formatting, linting, testing, and security scanning
- **Database Migrations**: Liquibase-managed schema evolution

## 🛠️ Technology Stack

- **Language**: Kotlin
- **Framework**: Spring Boot 3.5
- **Security**: Spring Security + JWT
- **Database**: PostgreSQL
- **Build Tool**: Gradle (Kotlin DSL)
- **Database Migration**: Liquibase
- **Containerization**: Docker & Docker Compose

## 🚀 Quick Start

### Prerequisites

- Java 21+
- Docker & Docker Compose

### Running with Docker

1. Clone the repository
2. Copy environment file: `cp .env.example .env`
3. Start the services: `docker-compose up -d`

The API will be available at `http://localhost:8080`

### API Documentation

Import the Postman collection from `docs/Auth_API_Collection.postman_collection.json` to explore the API endpoints.

## 📝 Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `POSTGRES_DB` | Database name | `rbac_db` |
| `POSTGRES_USER` | Database user | `rbac` |
| `POSTGRES_PASSWORD` | Database password | `rbac` |
| `JWT_SECRET` | JWT signing secret | `changeme-please-very-long-random` |
| `JWT_ISSUER` | JWT token issuer | `rbac-base` |

## 🏗️ Build & Development

### Local Development

```bash
# Build the project
./gradlew build

# Run tests
./gradlew test

# Run the application
./gradlew bootRun
```

### Docker Build

```bash
# Build Docker image
docker build -t auth-service .

# Run with Docker
docker run -p 8080:8080 auth-service
```

## 📁 Directory Structure

- `src/` - Source code
- `docs/` - Documentation and API collections
- `tools/` - Development tools and scripts
- `.github/workflows/` - CI/CD pipeline definitions
- `config/` - Code quality and tool configurations

## 🔄 CI/CD Pipeline

This project includes comprehensive GitHub Actions workflows:

- **Code Quality**: Automated formatting (ktlint), linting (Detekt), and security scanning
- **Test Coverage**: 90%+ coverage enforcement with detailed reporting
- **Database Migrations**: Automated Liquibase testing across PostgreSQL versions

See [CI/CD Documentation](docs/CI_CD_WORKFLOWS.md) for detailed information.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License.