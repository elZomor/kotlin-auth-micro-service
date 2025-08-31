package com.auth.domain.model

import com.auth.common.TestDataFactory
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Test
import java.util.UUID

class RoleWithPermissionsTest {
    @Test
    fun `should create RoleWithPermissions with all fields`() {
        // Given
        val id = UUID.randomUUID()
        val name = "ADMIN"
        val permissions = listOf(
            TestDataFactory.createPermission(name = "READ_USER"),
            TestDataFactory.createPermission(name = "WRITE_USER"),
            TestDataFactory.createPermission(name = "DELETE_USER")
        )

        // When
        val roleWithPermissions = RoleWithPermissions(
            id = id,
            name = name,
            createdAt = null,
            updatedAt = null,
            permissions = permissions
        )

        // Then
        assertEquals(id, roleWithPermissions.id)
        assertEquals(name, roleWithPermissions.name)
        assertEquals(permissions, roleWithPermissions.permissions)
    }

    @Test
    fun `should create RoleWithPermissions with empty permissions`() {
        // Given & When
        val roleWithPermissions = RoleWithPermissions(
            id = UUID.randomUUID(),
            name = "USER",
            createdAt = null,
            updatedAt = null,
            permissions = emptyList()
        )

        // Then
        assertNotNull(roleWithPermissions.id)
        assertEquals("USER", roleWithPermissions.name)
        assertEquals(0, roleWithPermissions.permissions.size)
    }

    @Test
    fun `should support data class operations`() {
        // Given
        val original = RoleWithPermissions(
            id = UUID.randomUUID(),
            name = "ADMIN",
            createdAt = null,
            updatedAt = null,
            permissions = listOf(TestDataFactory.createPermission(name = "READ_USER"))
        )

        // When
        val modified = original.copy(permissions = listOf(
            TestDataFactory.createPermission(name = "READ_USER"),
            TestDataFactory.createPermission(name = "WRITE_USER")
        ))

        // Then
        assertEquals(original.id, modified.id)
        assertEquals(original.name, modified.name)
        assertEquals(2, modified.permissions.size)
        assertEquals("READ_USER", modified.permissions[0].name)
        assertEquals("WRITE_USER", modified.permissions[1].name)
    }

    @Test
    fun `should handle different role types`() {
        // Given & When
        val adminRole = RoleWithPermissions(
            id = UUID.randomUUID(),
            name = "ADMIN",
            createdAt = null,
            updatedAt = null,
            permissions = listOf(TestDataFactory.createPermission(name = "ADMIN_ALL"))
        )
        val userRole = RoleWithPermissions(
            id = UUID.randomUUID(),
            name = "USER",
            createdAt = null,
            updatedAt = null,
            permissions = listOf(TestDataFactory.createPermission(name = "READ_OWN"))
        )
        val moderatorRole = RoleWithPermissions(
            id = UUID.randomUUID(),
            name = "MODERATOR",
            createdAt = null,
            updatedAt = null,
            permissions = listOf(
                TestDataFactory.createPermission(name = "READ_ALL"),
                TestDataFactory.createPermission(name = "WRITE_ALL")
            )
        )

        // Then
        assertEquals("ADMIN", adminRole.name)
        assertEquals("USER", userRole.name)
        assertEquals("MODERATOR", moderatorRole.name)
        assertEquals(1, adminRole.permissions.size)
        assertEquals(1, userRole.permissions.size)
        assertEquals(2, moderatorRole.permissions.size)
    }
}