package com.auth.domain.model

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Test
import java.util.UUID

class UserRolesGeneralModelTest {
    @Test
    fun `should create UserRolesGeneralModel with all fields`() {
        // Given
        val id = UUID.randomUUID()
        val email = "test@example.com"
        val username = "testuser"
        val roleName = "ADMIN"

        // When
        val model = UserRolesGeneralModel(
            id = id,
            email = email,
            username = username,
            roleName = roleName
        )

        // Then
        assertEquals(id, model.id)
        assertEquals(email, model.email)
        assertEquals(username, model.username)
        assertEquals(roleName, model.roleName)
    }

    @Test
    fun `should create UserRolesGeneralModel with null username`() {
        // Given & When
        val model = UserRolesGeneralModel(
            id = UUID.randomUUID(),
            email = "test@example.com",
            username = null,
            roleName = "USER"
        )

        // Then
        assertNotNull(model.id)
        assertEquals("test@example.com", model.email)
        assertEquals(null, model.username)
        assertEquals("USER", model.roleName)
    }

    @Test
    fun `should support data class operations`() {
        // Given
        val original = UserRolesGeneralModel(
            id = UUID.randomUUID(),
            email = "test@example.com",
            username = "testuser",
            roleName = "USER"
        )

        // When
        val modified = original.copy(
            username = "updateduser",
            roleName = "ADMIN"
        )

        // Then
        assertEquals(original.id, modified.id)
        assertEquals(original.email, modified.email)
        assertEquals("updateduser", modified.username)
        assertEquals("ADMIN", modified.roleName)
    }

    @Test
    fun `should handle different role assignments`() {
        // Given & When
        val userModel = UserRolesGeneralModel(
            id = UUID.randomUUID(),
            email = "user@example.com",
            username = "user",
            roleName = "USER"
        )
        val adminModel = UserRolesGeneralModel(
            id = UUID.randomUUID(),
            email = "admin@example.com",
            username = "admin",
            roleName = "ADMIN"
        )
        val moderatorModel = UserRolesGeneralModel(
            id = UUID.randomUUID(),
            email = "moderator@example.com",
            username = "moderator",
            roleName = "MODERATOR"
        )

        // Then
        assertEquals("USER", userModel.roleName)
        assertEquals("ADMIN", adminModel.roleName)
        assertEquals("MODERATOR", moderatorModel.roleName)
        assertEquals("user@example.com", userModel.email)
        assertEquals("admin@example.com", adminModel.email)
        assertEquals("moderator@example.com", moderatorModel.email)
    }
}