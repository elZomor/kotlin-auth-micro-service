package com.auth.domain.model

import com.auth.common.TestDataFactory
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.time.OffsetDateTime
import java.util.UUID

class PermissionTest {
    @Test
    fun `should create permission with all fields`() {
        // Given
        val id = UUID.randomUUID()
        val name = "READ_USER"
        val createdAt = OffsetDateTime.now()
        val updatedAt = OffsetDateTime.now()

        // When
        val permission =
            Permission(
                id = id,
                name = name,
                createdAt = createdAt,
                updatedAt = updatedAt,
            )

        // Then
        assertEquals(id, permission.id)
        assertEquals(name, permission.name)
        assertEquals(createdAt, permission.createdAt)
        assertEquals(updatedAt, permission.updatedAt)
    }

    @Test
    fun `should create permission with default id`() {
        // Given
        val name = "WRITE_USER"

        // When
        val permission = Permission(name = name)

        // Then
        assertNotNull(permission.id)
        assertEquals(name, permission.name)
        assertNull(permission.createdAt)
        assertNull(permission.updatedAt)
    }

    @Test
    fun `should support data class operations`() {
        // Given
        val originalPermission = TestDataFactory.createPermission(name = "READ_USER")

        // When
        val modifiedPermission = originalPermission.copy(name = "WRITE_USER")

        // Then
        assertNotEquals(originalPermission, modifiedPermission)
        assertEquals(originalPermission.id, modifiedPermission.id)
        assertEquals("WRITE_USER", modifiedPermission.name)
    }

    @Test
    fun `should have proper equals and hashCode`() {
        // Given
        val id = UUID.randomUUID()
        val timestamp = OffsetDateTime.now()
        val permission1 = TestDataFactory.createPermission(id = id, name = "READ_USER", createdAt = timestamp, updatedAt = timestamp)
        val permission2 = TestDataFactory.createPermission(id = id, name = "READ_USER", createdAt = timestamp, updatedAt = timestamp)
        val permission3 = TestDataFactory.createPermission(name = "WRITE_USER")

        // Then
        assertEquals(permission1, permission2)
        assertEquals(permission1.hashCode(), permission2.hashCode())
        assertNotEquals(permission1, permission3)
    }

    @Test
    fun `should handle different permission names`() {
        // Given & When
        val readPermission = TestDataFactory.createPermission(name = "READ_USER")
        val writePermission = TestDataFactory.createPermission(name = "WRITE_USER")
        val deletePermission = TestDataFactory.createPermission(name = "DELETE_USER")

        // Then
        assertEquals("READ_USER", readPermission.name)
        assertEquals("WRITE_USER", writePermission.name)
        assertEquals("DELETE_USER", deletePermission.name)

        assertNotEquals(readPermission, writePermission)
        assertNotEquals(writePermission, deletePermission)
    }

    @Test
    fun `should support common permission patterns`() {
        // Given & When
        val permissions =
            listOf(
                TestDataFactory.createPermission(name = "READ_USER"),
                TestDataFactory.createPermission(name = "WRITE_USER"),
                TestDataFactory.createPermission(name = "DELETE_USER"),
                TestDataFactory.createPermission(name = "ADMIN_ALL"),
                TestDataFactory.createPermission(name = "MANAGE_ROLES"),
            )

        // Then
        assertEquals(5, permissions.size)
        permissions.forEach { permission ->
            assertNotNull(permission.id)
            assertNotNull(permission.name)
            assertTrue(permission.name.isNotBlank())
        }
    }
}
