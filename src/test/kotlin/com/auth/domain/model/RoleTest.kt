package com.auth.domain.model

import com.auth.common.TestDataFactory
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test
import java.time.OffsetDateTime
import java.util.UUID

class RoleTest {
    @Test
    fun `should create role with all fields`() {
        // Given
        val id = UUID.randomUUID()
        val name = "ADMIN"
        val createdAt = OffsetDateTime.now()
        val updatedAt = OffsetDateTime.now()

        // When
        val role =
            Role(
                id = id,
                name = name,
                createdAt = createdAt,
                updatedAt = updatedAt,
            )

        // Then
        assertEquals(id, role.id)
        assertEquals(name, role.name)
        assertEquals(createdAt, role.createdAt)
        assertEquals(updatedAt, role.updatedAt)
    }

    @Test
    fun `should create role with default id`() {
        // Given
        val name = "USER"

        // When
        val role = Role(name = name)

        // Then
        assertNotNull(role.id)
        assertEquals(name, role.name)
        assertNull(role.createdAt)
        assertNull(role.updatedAt)
    }

    @Test
    fun `should support data class operations`() {
        // Given
        val originalRole = TestDataFactory.createRole(name = "USER")

        // When
        val modifiedRole = originalRole.copy(name = "ADMIN")

        // Then
        assertNotEquals(originalRole, modifiedRole)
        assertEquals(originalRole.id, modifiedRole.id)
        assertEquals("ADMIN", modifiedRole.name)
    }

    @Test
    fun `should have proper equals and hashCode`() {
        // Given
        val id = UUID.randomUUID()
        val role1 = TestDataFactory.createRole(id = id, name = "ADMIN")
        val role2 = TestDataFactory.createRole(id = id, name = "ADMIN")
        val role3 = TestDataFactory.createRole(name = "USER")

        // Then
        assertEquals(role1, role2)
        assertEquals(role1.hashCode(), role2.hashCode())
        assertNotEquals(role1, role3)
    }

    @Test
    fun `should handle different role names`() {
        // Given & When
        val adminRole = TestDataFactory.createRole(name = "ADMIN")
        val userRole = TestDataFactory.createRole(name = "USER")
        val moderatorRole = TestDataFactory.createRole(name = "MODERATOR")

        // Then
        assertEquals("ADMIN", adminRole.name)
        assertEquals("USER", userRole.name)
        assertEquals("MODERATOR", moderatorRole.name)

        assertNotEquals(adminRole, userRole)
        assertNotEquals(userRole, moderatorRole)
    }
}
