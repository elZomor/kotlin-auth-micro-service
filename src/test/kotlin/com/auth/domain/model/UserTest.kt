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

class UserTest {
    @Test
    fun `should create user with all fields`() {
        // Given
        val id = UUID.randomUUID()
        val email = "test@example.com"
        val username = "testuser"
        val password = "hashedpassword"
        val enabled = true
        val createdAt = OffsetDateTime.now()
        val updatedAt = OffsetDateTime.now()

        // When
        val user =
            User(
                id = id,
                email = email,
                username = username,
                password = password,
                enabled = enabled,
                createdAt = createdAt,
                updatedAt = updatedAt,
            )

        // Then
        assertEquals(id, user.id)
        assertEquals(email, user.email)
        assertEquals(username, user.username)
        assertEquals(password, user.password)
        assertEquals(enabled, user.enabled)
        assertEquals(createdAt, user.createdAt)
        assertEquals(updatedAt, user.updatedAt)
    }

    @Test
    fun `should create user with default values`() {
        // Given
        val email = "test@example.com"
        val password = "hashedpassword"

        // When
        val user = User(email = email, password = password)

        // Then
        assertNotNull(user.id)
        assertEquals(email, user.email)
        assertNull(user.username)
        assertEquals(password, user.password)
        assertTrue(user.enabled)
        assertNull(user.createdAt)
        assertNull(user.updatedAt)
    }

    @Test
    fun `should support data class operations`() {
        // Given
        val originalUser = TestDataFactory.createUser()

        // When
        val modifiedUser = originalUser.copy(username = "newusername")

        // Then
        assertNotEquals(originalUser, modifiedUser)
        assertEquals(originalUser.id, modifiedUser.id)
        assertEquals(originalUser.email, modifiedUser.email)
        assertEquals(originalUser.password, modifiedUser.password)
        assertEquals("newusername", modifiedUser.username)
    }

    @Test
    fun `should have proper equals and hashCode`() {
        // Given
        val id = UUID.randomUUID()
        val user1 = TestDataFactory.createUser(id = id, email = "test@example.com")
        val user2 = TestDataFactory.createUser(id = id, email = "test@example.com")
        val user3 = TestDataFactory.createUser(email = "different@example.com")

        // Then
        assertEquals(user1, user2)
        assertEquals(user1.hashCode(), user2.hashCode())
        assertNotEquals(user1, user3)
        assertNotEquals(user1.hashCode(), user3.hashCode())
    }

    @Test
    fun `should have meaningful toString`() {
        // Given
        val user = TestDataFactory.createUser(email = "test@example.com", username = "testuser")

        // When
        val userString = user.toString()

        // Then
        assertTrue(userString.contains("test@example.com"))
        assertTrue(userString.contains("testuser"))
        assertTrue(userString.contains("User"))
    }
}
