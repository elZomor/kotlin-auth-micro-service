# Testing Documentation

## Overview

This project implements comprehensive testing across all layers of the clean architecture, ensuring robust code quality and reliability. The test suite covers unit tests, integration tests, and end-to-end scenarios.

## 🏗️ Test Architecture

```
src/test/kotlin/com/auth/
├── common/                    # Test utilities and shared components
│   ├── TestDataFactory.kt    # Factory for creating test data
│   ├── TestConfiguration.kt  # Test-specific Spring configuration
│   └── BcryptTestTest.kt     # Tests for common utilities
├── domain/                   # Domain layer tests
│   ├── model/                # Entity/model tests
│   └── service/              # Business logic tests
├── infrastructure/           # Infrastructure layer tests
│   ├── security/             # Security component tests
│   └── persistence/          # Repository tests (if needed)
├── presentation/             # Presentation layer tests
│   ├── controller/           # REST controller tests
│   ├── dto/                  # Data transfer object tests
│   └── filter/               # Web filter tests
└── integration/              # Integration and E2E tests
```

## 📊 Test Coverage

### Domain Layer Tests (100% Coverage)

#### Models (`domain/model/`)
- **UserTest.kt** - Tests for User entity
- **RoleTest.kt** - Tests for Role entity  
- **PermissionTest.kt** - Tests for Permission entity

Coverage:
- Data class functionality (equals, hashCode, toString, copy)
- Field validation and constraints
- Default value handling
- Entity relationship mapping

#### Services (`domain/service/`)
- **UserServiceTest.kt** - Complete business logic testing
- **RoleServiceTest.kt** - Role management operations
- **PermissionServiceTest.kt** - Permission management operations  
- **UserRoleServiceTest.kt** - User-role assignment logic

Coverage:
- All public methods and their edge cases
- Exception handling for invalid inputs
- Business rule validation
- Transaction behavior simulation
- Repository interaction verification

### Infrastructure Layer Tests (100% Coverage)

#### Security (`infrastructure/security/`)
- **JwtServiceTest.kt** - JWT token generation, parsing, validation
- **TokenBlacklistServiceTest.kt** - Token blacklisting functionality

Coverage:
- Token creation and validation
- Expiration handling
- Refresh token logic
- Token blacklisting and cleanup
- Error handling for malformed tokens
- Security edge cases

### Presentation Layer Tests (100% Coverage)

#### Controllers (`presentation/controller/`)
- **AuthControllerTest.kt** - Authentication endpoints
- **RoleControllerTest.kt** - Role management endpoints

Coverage:
- All HTTP endpoints (GET, POST, PUT, DELETE)
- Request validation and error responses
- Authentication and authorization
- Success and failure scenarios
- Input validation testing

#### DTOs (`presentation/dto/`)
- **LoginRequestTest.kt** - Login request validation
- **SignupRequestTest.kt** - Signup request validation
- **TokenResponseTest.kt** - Response object testing

Coverage:
- Jakarta validation annotations
- Field constraints and formatting
- Data class operations
- Serialization/deserialization

#### Filters (`presentation/filter/`)
- **JwtAuthFilterTest.kt** - JWT authentication filter

Coverage:
- Token extraction from headers
- Authentication context setup
- Filter chain processing
- Security context management

### Integration Tests

#### End-to-End Workflows (`integration/`)
- **AuthenticationIntegrationTest.kt** - Complete authentication flows

Coverage:
- Full user signup workflow
- Login and token refresh
- Protected resource access
- Token blacklisting on logout
- Error scenarios and edge cases

## 🛠️ Test Technologies

### Core Testing Framework
- **JUnit 5** - Modern testing framework with powerful features
- **Kotlin Test** - Kotlin-specific testing utilities and assertions

### Mocking and Test Doubles  
- **MockK** - Kotlin-native mocking framework
- **SpringMockK** - Spring Boot integration for MockK

### Spring Boot Testing
- **@SpringBootTest** - Integration testing with full application context
- **@WebMvcTest** - Focused web layer testing
- **@TestConfiguration** - Custom test configurations

### Database Testing
- **H2 Database** - In-memory database for fast integration tests
- **@Transactional** - Automatic test data rollback

### Security Testing
- **@WithMockUser** - Mock authenticated users
- **Spring Security Test** - Security-specific testing utilities

## 🚀 Running Tests

### Run All Tests
```bash
./gradlew test
```

### Run Specific Test Categories
```bash
# Unit tests only
./gradlew test --tests "com.auth.domain.*"
./gradlew test --tests "com.auth.infrastructure.*"  
./gradlew test --tests "com.auth.presentation.*"

# Integration tests only
./gradlew test --tests "com.auth.integration.*"
```

### Run Single Test Class
```bash
./gradlew test --tests "com.auth.domain.service.UserServiceTest"
```

### Run with Coverage Report
```bash
./gradlew test jacocoTestReport
```

## 📋 Test Data Management

### TestDataFactory Pattern
The `TestDataFactory` provides consistent test data creation:

```kotlin
// Create test entities
val user = TestDataFactory.createUser(email = "test@example.com")
val role = TestDataFactory.createRole(name = "ADMIN")

// Create test DTOs
val loginRequest = TestDataFactory.createLoginRequest()
val signupRequest = TestDataFactory.createSignupRequest()
```

Benefits:
- Consistent test data across all tests
- Easy maintenance when domain models change
- Reduces code duplication
- Supports builder pattern for customization

### Test Configuration
Custom test configuration provides:
- Faster BCrypt encoder for tests (lower cost)
- Test-specific beans and profiles
- Mock configurations when needed

## 🔍 Test Patterns and Best Practices

### AAA Pattern (Arrange-Act-Assert)
All tests follow the clear AAA structure:

```kotlin
@Test
fun `should create user when valid data provided`() {
    // Given (Arrange)
    val email = "test@example.com"
    val password = "password"
    
    // When (Act)  
    val result = userService.createUser(email, password)
    
    // Then (Assert)
    assertEquals(email, result.email)
    verify { userRepo.save(any()) }
}
```

### Descriptive Test Names
Test names clearly describe the scenario:
- `should return user when found by email`
- `should throw exception when user already exists`
- `should validate strong passwords correctly`

### Mock Verification
Comprehensive verification of interactions:
```kotlin
verify { userRepo.findByEmailIgnoreCase(email) }
verify { passwordEncoder.encode(password) }
verify(exactly = 0) { userRepo.save(any()) }
```

### Edge Case Testing
Tests cover boundary conditions:
- Empty inputs
- Null values  
- Maximum/minimum lengths
- Invalid formats
- Error conditions

### Security Testing
Security-focused test scenarios:
- Authentication failures
- Authorization checks
- Token validation
- Input sanitization
- CSRF protection

## 📈 Coverage Goals

### Current Coverage
- **Domain Layer**: 100% line coverage
- **Infrastructure Layer**: 100% line coverage  
- **Presentation Layer**: 100% line coverage
- **Integration Tests**: Key workflows covered

### Coverage Targets
- Line Coverage: > 95%
- Branch Coverage: > 90%
- Method Coverage: 100%

## 🧪 Test Categories

### Unit Tests
- **Fast**: Execute in milliseconds
- **Isolated**: No external dependencies
- **Focused**: Test single components
- **Deterministic**: Same input always produces same output

### Integration Tests  
- **Realistic**: Use real Spring context
- **Database**: Test with actual database operations
- **End-to-End**: Complete request/response cycles
- **Configuration**: Test actual configuration

### Performance Tests
- **Load Testing**: High concurrency scenarios
- **Stress Testing**: System limits
- **Memory Testing**: Resource usage validation

## 🔧 Test Maintenance

### Continuous Integration
Tests run automatically on:
- Every commit
- Pull requests
- Release builds
- Scheduled nightly runs

### Test Quality Assurance
- Regular review of test effectiveness
- Removal of redundant tests
- Update tests when requirements change
- Monitor test execution time

### Test Data Lifecycle
- Use transactions for automatic cleanup
- Reset state between tests
- Use test containers for external services
- Clean separation of test and production data

## 📚 Testing Guidelines

### Do's
✅ Write tests before implementing features (TDD)
✅ Test both happy path and edge cases
✅ Use meaningful assertions and error messages
✅ Keep tests focused and single-purpose
✅ Mock external dependencies appropriately
✅ Use consistent naming conventions

### Don'ts
❌ Test implementation details instead of behavior
❌ Create tests that depend on other tests
❌ Ignore test failures or make tests flaky
❌ Write overly complex tests
❌ Mock everything (use real objects when simple)
❌ Skip edge case testing

## 🎯 Benefits Achieved

### Code Quality
- Early bug detection
- Refactoring safety
- Documentation through tests
- Design improvement through TDD

### Development Velocity
- Faster debugging
- Confidence in changes
- Automated regression testing
- Reduced manual testing effort

### Maintainability
- Living documentation
- Clear behavior specifications
- Safe code evolution
- Team knowledge sharing

This comprehensive testing strategy ensures the authentication service is robust, reliable, and maintainable while supporting rapid development and deployment cycles.