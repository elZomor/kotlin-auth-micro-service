package com.auth.presentation.dto

import com.auth.common.TestDataFactory
import jakarta.validation.Validation
import jakarta.validation.Validator
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class LoginRequestTest {
    private lateinit var validator: Validator

    @BeforeEach
    fun setup() {
        validator = Validation.buildDefaultValidatorFactory().validator
    }

    @Test
    fun `should create valid login request`() {
        // Given & When
        val loginRequest =
            TestDataFactory.createLoginRequest(
                email = "test@example.com",
                password = "password123",
            )

        // Then
        assertEquals("test@example.com", loginRequest.email)
        assertEquals("password123", loginRequest.password)
    }

    @Test
    fun `should validate valid login request`() {
        // Given
        val loginRequest =
            TestDataFactory.createLoginRequest(
                email = "valid@example.com",
                password = "validpassword",
            )

        // When
        val violations = validator.validate(loginRequest)

        // Then
        assertTrue(violations.isEmpty())
    }

    @Test
    fun `should fail validation for invalid email format`() {
        // Given
        val loginRequest =
            LoginRequest(
                email = "invalid-email",
                password = "password123",
            )

        // When
        val violations = validator.validate(loginRequest)

        // Then
        assertTrue(violations.isNotEmpty())
        assertTrue(violations.any { it.propertyPath.toString() == "email" })
    }

    @Test
    fun `should fail validation for blank email`() {
        // Given
        val loginRequest =
            LoginRequest(
                email = "",
                password = "password123",
            )

        // When
        val violations = validator.validate(loginRequest)

        // Then
        assertTrue(violations.isNotEmpty())
        assertTrue(violations.any { it.propertyPath.toString() == "email" })
    }

    @Test
    fun `should fail validation for blank password`() {
        // Given
        val loginRequest =
            LoginRequest(
                email = "test@example.com",
                password = "",
            )

        // When
        val violations = validator.validate(loginRequest)

        // Then
        assertTrue(violations.isNotEmpty())
        assertTrue(violations.any { it.propertyPath.toString() == "password" })
    }

    @Test
    fun `should support data class operations`() {
        // Given
        val original = TestDataFactory.createLoginRequest()

        // When
        val modified = original.copy(email = "newemail@example.com")

        // Then
        assertEquals("newemail@example.com", modified.email)
        assertEquals(original.password, modified.password)
    }

    @Test
    fun `should have proper equals and hashCode`() {
        // Given
        val request1 =
            TestDataFactory.createLoginRequest(
                email = "test@example.com",
                password = "password",
            )
        val request2 =
            TestDataFactory.createLoginRequest(
                email = "test@example.com",
                password = "password",
            )
        val request3 =
            TestDataFactory.createLoginRequest(
                email = "different@example.com",
                password = "password",
            )

        // Then
        assertEquals(request1, request2)
        assertEquals(request1.hashCode(), request2.hashCode())
        assertTrue(request1 != request3)
    }

    @Test
    fun `should handle various valid email formats`() {
        // Given
        val validEmails =
            listOf(
                "user@example.com",
                "user.name@example.com",
                "user+tag@example.com",
                "user123@example-domain.com",
                "a@b.co",
            )

        validEmails.forEach { email ->
            // When
            val loginRequest = LoginRequest(email = email, password = "password123")
            val violations = validator.validate(loginRequest)

            // Then
            assertTrue(violations.isEmpty(), "Email $email should be valid")
        }
    }
}
