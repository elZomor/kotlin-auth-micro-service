package com.auth.domain.model

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Test
import java.util.UUID

class UserRolesPermissionsGeneralModelTest {
    @Test
    fun `should create UserRolesPermissionsGeneralModel with all fields`() {
        // Given
        val id = UUID.randomUUID()
        val email = "test@example.com"
        val username = "testuser"
        val roleName = "ADMIN"
        val permissionName = "READ_USER"

        // When
        val model = UserRolesPermissionsGeneralModel(
            id = id,
            email = email,
            username = username,
            roleName = roleName,
            enabled = true,
            permissionName = permissionName
        )

        // Then
        assertEquals(id, model.id)
        assertEquals(email, model.email)
        assertEquals(username, model.username)
        assertEquals(roleName, model.roleName)
        assertEquals(true, model.enabled)
        assertEquals(permissionName, model.permissionName)
    }

    @Test
    fun `should create UserRolesPermissionsGeneralModel with null username`() {
        // Given & When
        val model = UserRolesPermissionsGeneralModel(
            id = UUID.randomUUID(),
            email = "test@example.com",
            username = null,
            roleName = "USER",
            enabled = false,
            permissionName = "READ_OWN"
        )

        // Then
        assertNotNull(model.id)
        assertEquals("test@example.com", model.email)
        assertEquals(null, model.username)
        assertEquals("USER", model.roleName)
        assertEquals(false, model.enabled)
        assertEquals("READ_OWN", model.permissionName)
    }

    @Test
    fun `should support data class operations`() {
        // Given
        val original = UserRolesPermissionsGeneralModel(
            id = UUID.randomUUID(),
            email = "test@example.com",
            username = "testuser",
            roleName = "USER",
            enabled = true,
            permissionName = "READ_USER"
        )

        // When
        val modified = original.copy(
            username = "updateduser",
            permissionName = "WRITE_USER"
        )

        // Then
        assertEquals(original.id, modified.id)
        assertEquals(original.email, modified.email)
        assertEquals("updateduser", modified.username)
        assertEquals(original.roleName, modified.roleName)
        assertEquals(original.enabled, modified.enabled)
        assertEquals("WRITE_USER", modified.permissionName)
    }

    @Test
    fun `should handle different permission types`() {
        // Given & When
        val readModel = UserRolesPermissionsGeneralModel(
            id = UUID.randomUUID(),
            email = "user@example.com",
            username = "user",
            roleName = "USER",
            enabled = true,
            permissionName = "READ_USER"
        )
        val writeModel = UserRolesPermissionsGeneralModel(
            id = UUID.randomUUID(),
            email = "admin@example.com",
            username = "admin",
            roleName = "ADMIN",
            enabled = true,
            permissionName = "WRITE_USER"
        )
        val deleteModel = UserRolesPermissionsGeneralModel(
            id = UUID.randomUUID(),
            email = "superadmin@example.com",
            username = "superadmin",
            roleName = "SUPER_ADMIN",
            enabled = true,
            permissionName = "DELETE_USER"
        )

        // Then
        assertEquals("READ_USER", readModel.permissionName)
        assertEquals("WRITE_USER", writeModel.permissionName)
        assertEquals("DELETE_USER", deleteModel.permissionName)
        assertEquals("USER", readModel.roleName)
        assertEquals("ADMIN", writeModel.roleName)
        assertEquals("SUPER_ADMIN", deleteModel.roleName)
    }
}