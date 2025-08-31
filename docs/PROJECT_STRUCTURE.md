# Project Structure Documentation

## Overview

This project follows **Clean Architecture** principles, organizing code into distinct layers with clear separation of concerns.

## Directory Structure

```
src/main/kotlin/com/auth/
├── AuthApplication.kt              # 🚀 Main application entry point
├── common/                         # 🔧 Shared utilities
│   └── BcryptTest.kt              # Password testing utility
├── domain/                         # 💼 Core business logic layer
│   ├── model/                     # 📋 Domain entities
│   │   ├── User.kt
│   │   ├── Role.kt
│   │   ├── Permission.kt
│   │   ├── UserRole.kt
│   │   ├── RolePermission.kt
│   │   └── ...
│   ├── repository/                # 🔌 Repository interfaces
│   └── service/                   # 🏗️ Domain services
│       ├── UserService.kt
│       ├── RoleService.kt
│       ├── PermissionService.kt
│       └── UserRoleService.kt
├── infrastructure/                # 🔧 External concerns layer
│   ├── config/                    # ⚙️ Spring configurations
│   │   └── SecurityConfig.kt
│   ├── persistence/               # 💾 Database implementations
│   │   ├── UserRepo.kt
│   │   ├── RoleRepo.kt
│   │   ├── PermissionRepo.kt
│   │   └── ...
│   └── security/                  # 🔒 Security services
│       ├── JwtService.kt
│       ├── TokenBlacklistService.kt
│       ├── AppUserDetailsService.kt
│       ├── AuthorizationUtils.kt
│       └── Permissions.kt
└── presentation/                  # 🌐 Web layer
    ├── controller/                # 📡 REST controllers
    │   ├── AuthController.kt
    │   ├── UserRoleController.kt
    │   ├── RoleController.kt
    │   └── PermissionController.kt
    ├── dto/                      # 📦 Data transfer objects
    │   ├── LoginRequest.kt
    │   ├── SignupRequest.kt
    │   ├── TokenResponse.kt
    │   └── ...
    └── filter/                   # 🔍 Web filters
        └── JwtAuthFilter.kt
```

## Layer Responsibilities

### 🚀 Application Layer
- **Location**: Root level (`AuthApplication.kt`)
- **Purpose**: Application entry point and main configuration

### 🔧 Common Layer  
- **Location**: `common/`
- **Purpose**: Shared utilities, constants, and helper classes
- **Examples**: Password testing utilities, common validators

### 💼 Domain Layer
- **Location**: `domain/`
- **Purpose**: Core business logic and rules
- **Components**:
  - **Models**: Core entities representing business concepts
  - **Services**: Business logic and domain operations
  - **Repository Interfaces**: Contracts for data access (implemented in infrastructure)

### 🔧 Infrastructure Layer
- **Location**: `infrastructure/`
- **Purpose**: Technical details and external system integrations
- **Components**:
  - **Config**: Spring Boot configurations
  - **Persistence**: Database repositories and data access
  - **Security**: Authentication and authorization logic

### 🌐 Presentation Layer
- **Location**: `presentation/`
- **Purpose**: Web interface and API endpoints
- **Components**:
  - **Controllers**: REST API endpoints
  - **DTOs**: Request/response objects
  - **Filters**: Web request/response processing

## Benefits of This Structure

### 🏗️ Clean Architecture Benefits
- **Separation of Concerns**: Each layer has a single responsibility
- **Dependency Inversion**: Business logic doesn't depend on frameworks
- **Testability**: Easy to unit test business logic in isolation
- **Maintainability**: Changes in one layer don't affect others

### 📦 Package Benefits  
- **Clear Navigation**: Developers can easily find related code
- **Reduced Coupling**: Dependencies flow inward toward the domain
- **Framework Independence**: Business logic is isolated from Spring Boot
- **Easy Testing**: Mock external dependencies at layer boundaries

## Dependency Flow

```
Presentation → Infrastructure → Domain
     ↓              ↓           ↑
   Controllers   Repositories  Models
   DTOs          Config        Services
   Filters       Security      
```

- **Inward Dependencies**: All dependencies point toward the domain layer
- **No Outward Dependencies**: Domain layer doesn't know about presentation or infrastructure
- **Interface Segregation**: Each layer only depends on what it needs

## File Organization Principles

1. **Single Responsibility**: Each file has one clear purpose
2. **Domain-Driven**: Organized around business concepts, not technical layers
3. **Discoverability**: Related files are grouped together
4. **Scalability**: Structure supports growth without reorganization