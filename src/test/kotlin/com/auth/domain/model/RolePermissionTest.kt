package com.auth.domain.model

import com.auth.common.TestDataFactory
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Test
import java.time.OffsetDateTime
import java.util.UUID

class RolePermissionTest {
    @Test
    fun `should create RolePermission with all fields`() {
        // Given
        val id = UUID.randomUUID()
        val roleId = UUID.randomUUID()
        val permissionId = UUID.randomUUID()

        // When
        val rolePermission = RolePermission(
            id = id,
            roleId = roleId,
            permissionId = permissionId
        )

        // Then
        assertEquals(id, rolePermission.id)
        assertEquals(roleId, rolePermission.roleId)
        assertEquals(permissionId, rolePermission.permissionId)
    }

    @Test
    fun `should create RolePermission with default id`() {
        // Given
        val roleId = UUID.randomUUID()
        val permissionId = UUID.randomUUID()

        // When
        val rolePermission = RolePermission(
            roleId = roleId,
            permissionId = permissionId
        )

        // Then
        assertNotNull(rolePermission.id)
        assertEquals(roleId, rolePermission.roleId)
        assertEquals(permissionId, rolePermission.permissionId)
    }

    @Test
    fun `should support data class operations`() {
        // Given
        val originalRolePermission = TestDataFactory.createRolePermission(
            roleId = UUID.randomUUID(),
            permissionId = UUID.randomUUID()
        )

        // When
        val modifiedRolePermission = originalRolePermission.copy(
            permissionId = UUID.randomUUID()
        )

        // Then
        assertNotEquals(originalRolePermission, modifiedRolePermission)
        assertEquals(originalRolePermission.id, modifiedRolePermission.id)
        assertEquals(originalRolePermission.roleId, modifiedRolePermission.roleId)
        assertNotEquals(originalRolePermission.permissionId, modifiedRolePermission.permissionId)
    }

    @Test
    fun `should have proper equals and hashCode`() {
        // Given
        val id = UUID.randomUUID()
        val roleId = UUID.randomUUID()
        val permissionId = UUID.randomUUID()

        val rolePermission1 = TestDataFactory.createRolePermission(
            id = id,
            roleId = roleId,
            permissionId = permissionId
        )
        val rolePermission2 = TestDataFactory.createRolePermission(
            id = id,
            roleId = roleId,
            permissionId = permissionId
        )
        val rolePermission3 = TestDataFactory.createRolePermission(
            roleId = UUID.randomUUID(),
            permissionId = permissionId
        )

        // Then
        assertEquals(rolePermission1, rolePermission2)
        assertEquals(rolePermission1.hashCode(), rolePermission2.hashCode())
        assertNotEquals(rolePermission1, rolePermission3)
    }

    @Test
    fun `should handle different role-permission combinations`() {
        // Given & When
        val adminReadPermission = TestDataFactory.createRolePermission(
            roleId = UUID.randomUUID(),
            permissionId = UUID.randomUUID()
        )
        val adminWritePermission = TestDataFactory.createRolePermission(
            roleId = UUID.randomUUID(),
            permissionId = UUID.randomUUID()
        )
        val userReadPermission = TestDataFactory.createRolePermission(
            roleId = UUID.randomUUID(),
            permissionId = UUID.randomUUID()
        )

        // Then
        assertNotNull(adminReadPermission.id)
        assertNotNull(adminWritePermission.id)
        assertNotNull(userReadPermission.id)
        assertNotNull(adminReadPermission.roleId)
        assertNotNull(adminWritePermission.roleId)
        assertNotNull(userReadPermission.roleId)
        assertNotNull(adminReadPermission.permissionId)
        assertNotNull(adminWritePermission.permissionId)
        assertNotNull(userReadPermission.permissionId)
    }

    @Test
    fun `should support common role-permission patterns`() {
        // Given & When
        val rolePermissions = listOf(
            TestDataFactory.createRolePermission(),
            TestDataFactory.createRolePermission(),
            TestDataFactory.createRolePermission(),
            TestDataFactory.createRolePermission(),
            TestDataFactory.createRolePermission()
        )

        // Then
        assertEquals(5, rolePermissions.size)
        rolePermissions.forEach { rolePermission ->
            assertNotNull(rolePermission.id)
            assertNotNull(rolePermission.roleId)
            assertNotNull(rolePermission.permissionId)
        }
    }
}