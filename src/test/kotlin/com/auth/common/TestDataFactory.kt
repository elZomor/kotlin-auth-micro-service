package com.auth.common

import com.auth.domain.model.*
import com.auth.presentation.dto.*
import java.time.OffsetDateTime
import java.util.*

/**
 * Factory for creating test data objects
 */
object TestDataFactory {
    
    // Domain Model Factories
    fun createUser(
        id: UUID = UUID.randomUUID(),
        email: String = "test@example.com",
        username: String? = "testuser",
        password: String = "encodedPassword",
        enabled: Boolean = true,
        createdAt: OffsetDateTime? = OffsetDateTime.now(),
        updatedAt: OffsetDateTime? = OffsetDateTime.now()
    ) = User(
        id = id,
        email = email,
        username = username,
        password = password,
        enabled = enabled,
        createdAt = createdAt,
        updatedAt = updatedAt
    )
    
    fun createRole(
        id: UUID = UUID.randomUUID(),
        name: String = "USER",
        createdAt: OffsetDateTime? = OffsetDateTime.now(),
        updatedAt: OffsetDateTime? = OffsetDateTime.now()
    ) = Role(
        id = id,
        name = name,
        createdAt = createdAt,
        updatedAt = updatedAt
    )
    
    fun createPermission(
        id: UUID = UUID.randomUUID(),
        name: String = "READ_USER",
        createdAt: OffsetDateTime? = OffsetDateTime.now(),
        updatedAt: OffsetDateTime? = OffsetDateTime.now()
    ) = Permission(
        id = id,
        name = name,
        createdAt = createdAt,
        updatedAt = updatedAt
    )
    
    fun createUserRole(
        id: UUID = UUID.randomUUID(),
        userId: UUID = UUID.randomUUID(),
        roleId: UUID = UUID.randomUUID(),
        createdAt: OffsetDateTime? = OffsetDateTime.now()
    ) = UserRole(
        id = id,
        userId = userId,
        roleId = roleId,
        createdAt = createdAt
    )
    
    fun createRolePermission(
        id: UUID = UUID.randomUUID(),
        roleId: UUID = UUID.randomUUID(),
        permissionId: UUID = UUID.randomUUID(),
        createdAt: OffsetDateTime? = OffsetDateTime.now()
    ) = RolePermission(
        id = id,
        roleId = roleId,
        permissionId = permissionId,
        createdAt = createdAt
    )
    
    // DTO Factories
    fun createLoginRequest(
        email: String = "test@example.com",
        password: String = "password123"
    ) = LoginRequest(email = email, password = password)
    
    fun createSignupRequest(
        email: String = "test@example.com",
        password: String = "password123",
        username: String? = "testuser"
    ) = SignupRequest(email = email, password = password, username = username)
    
    fun createTokenResponse(
        accessToken: String = "access-token",
        refreshToken: String = "refresh-token",
        type: String = "Bearer",
        expiresIn: Long = 3600
    ) = TokenResponse(
        accessToken = accessToken,
        refreshToken = refreshToken,
        type = type,
        expiresIn = expiresIn
    )
    
    fun createRefreshTokenRequest(
        refreshToken: String = "refresh-token"
    ) = RefreshTokenRequest(refreshToken = refreshToken)
    
    fun createUpdateUsernameRequest(
        username: String = "newusername"
    ) = UpdateUsernameRequest(username = username)
    
    fun createCreateRoleRequest(
        name: String = "ADMIN"
    ) = CreateRoleRequest(name = name)
    
    fun createCreatePermissionRequest(
        name: String = "WRITE_USER"
    ) = CreatePermissionRequest(name = name)
    
    fun createAssignUserRoleRequest(
        userId: UUID = UUID.randomUUID(),
        roleId: UUID = UUID.randomUUID()
    ) = AssignUserRoleRequest(userId = userId, roleId = roleId)
    
    fun createUserResponse(
        id: UUID = UUID.randomUUID(),
        email: String = "test@example.com",
        username: String? = "testuser",
        enabled: Boolean = true
    ) = UserResponse(
        id = id,
        email = email,
        username = username,
        enabled = enabled
    )
}