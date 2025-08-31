package com.auth.presentation.dto

import com.auth.common.TestDataFactory
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Test
import java.util.UUID

class UnusedDtoTest {
    
    @Test
    fun `UserResponse should create and work correctly`() {
        // Given & When
        val userResponse = TestDataFactory.createUserResponse()
        
        // Then
        assertNotNull(userResponse.id)
        assertNotNull(userResponse.email)
        assertNotNull(userResponse.username)
        assertNotNull(userResponse.enabled)
        assertNotNull(userResponse.createdAt)
        assertNotNull(userResponse.updatedAt)
    }
    
    @Test
    fun `CreateUserRequest should create and work correctly`() {
        // Given & When
        val createUserRequest = CreateUserRequest(
            email = "test@example.com",
            password = "password123",
            username = "testuser"
        )
        
        // Then
        assertEquals("test@example.com", createUserRequest.email)
        assertEquals("password123", createUserRequest.password)
        assertEquals("testuser", createUserRequest.username)
    }
    
    @Test
    fun `AssignPermissionRequest should create and work correctly`() {
        // Given
        val roleId = UUID.randomUUID()
        val permissionId = UUID.randomUUID()
        
        // When
        val assignPermissionRequest = AssignPermissionRequest(
            roleId = roleId,
            permissionId = permissionId
        )
        
        // Then
        assertEquals(roleId, assignPermissionRequest.roleId)
        assertEquals(permissionId, assignPermissionRequest.permissionId)
    }
    
    @Test
    fun `AssignRoleRequest should create and work correctly`() {
        // Given
        val userId = UUID.randomUUID()
        val roleId = UUID.randomUUID()
        
        // When
        val assignRoleRequest = AssignRoleRequest(
            userId = userId,
            roleId = roleId
        )
        
        // Then
        assertEquals(userId, assignRoleRequest.userId)
        assertEquals(roleId, assignRoleRequest.roleId)
    }
}