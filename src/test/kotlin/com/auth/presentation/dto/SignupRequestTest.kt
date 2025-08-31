package com.auth.presentation.dto

import com.auth.common.TestDataFactory
import jakarta.validation.Validation
import jakarta.validation.Validator
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class SignupRequestTest {
    private lateinit var validator: Validator

    @BeforeEach
    fun setup() {
        validator = Validation.buildDefaultValidatorFactory().validator
    }

    @Test
    fun `should create valid signup request with username`() {
        // Given & When
        val signupRequest =
            TestDataFactory.createSignupRequest(
                email = "test@example.com",
                password = "password123",
                username = "testuser",
            )

        // Then
        assertEquals("test@example.com", signupRequest.email)
        assertEquals("password123", signupRequest.password)
        assertEquals("testuser", signupRequest.username)
    }

    @Test
    fun `should create valid signup request without username`() {
        // Given & When
        val signupRequest =
            TestDataFactory.createSignupRequest(
                email = "test@example.com",
                password = "password123",
                username = null,
            )

        // Then
        assertEquals("test@example.com", signupRequest.email)
        assertEquals("password123", signupRequest.password)
        assertNull(signupRequest.username)
    }

    @Test
    fun `should validate valid signup request`() {
        // Given
        val signupRequest =
            TestDataFactory.createSignupRequest(
                email = "valid@example.com",
                password = "StrongPassword123!",
                username = "validuser",
            )

        // When
        val violations = validator.validate(signupRequest)

        // Then
        assertTrue(violations.isEmpty())
    }

    @Test
    fun `should fail validation for invalid email format`() {
        // Given
        val signupRequest =
            SignupRequest(
                email = "invalid-email",
                password = "StrongPassword123!",
                username = "testuser",
            )

        // When
        val violations = validator.validate(signupRequest)

        // Then
        assertTrue(violations.isNotEmpty())
        assertTrue(violations.any { it.propertyPath.toString() == "email" })
    }

    @Test
    fun `should fail validation for blank email`() {
        // Given
        val signupRequest =
            SignupRequest(
                email = "",
                password = "StrongPassword123!",
                username = "testuser",
            )

        // When
        val violations = validator.validate(signupRequest)

        // Then
        assertTrue(violations.isNotEmpty())
        assertTrue(violations.any { it.propertyPath.toString() == "email" })
    }

    @Test
    fun `should fail validation for weak password`() {
        // Given
        val signupRequest =
            SignupRequest(
                email = "test@example.com",
                password = "weak",
                username = "testuser",
            )

        // When
        val violations = validator.validate(signupRequest)

        // Then
        assertTrue(violations.isNotEmpty())
        assertTrue(violations.any { it.propertyPath.toString() == "password" })
    }

    @Test
    fun `should fail validation for blank password`() {
        // Given
        val signupRequest =
            SignupRequest(
                email = "test@example.com",
                password = "",
                username = "testuser",
            )

        // When
        val violations = validator.validate(signupRequest)

        // Then
        assertTrue(violations.isNotEmpty())
        assertTrue(violations.any { it.propertyPath.toString() == "password" })
    }

    @Test
    fun `should validate null username as optional`() {
        // Given
        val signupRequest =
            SignupRequest(
                email = "test@example.com",
                password = "StrongPassword123!",
                username = null,
            )

        // When
        val violations = validator.validate(signupRequest)

        // Then
        assertTrue(violations.isEmpty())
    }

    @Test
    fun `should fail validation for short username`() {
        // Given
        val signupRequest =
            SignupRequest(
                email = "test@example.com",
                password = "StrongPassword123!",
                username = "a",
            )

        // When
        val violations = validator.validate(signupRequest)

        // Then
        assertTrue(violations.isNotEmpty())
        assertTrue(violations.any { it.propertyPath.toString() == "username" })
    }

    @Test
    fun `should fail validation for long username`() {
        // Given
        val longUsername = "a".repeat(31) // Too long (assuming max is 30)
        val signupRequest =
            SignupRequest(
                email = "test@example.com",
                password = "StrongPassword123!",
                username = longUsername,
            )

        // When
        val violations = validator.validate(signupRequest)

        // Then
        assertTrue(violations.isNotEmpty())
        assertTrue(violations.any { it.propertyPath.toString() == "username" })
    }

    @Test
    fun `should support data class operations`() {
        // Given
        val original = TestDataFactory.createSignupRequest()

        // When
        val modified = original.copy(username = "newusername")

        // Then
        assertEquals("newusername", modified.username)
        assertEquals(original.email, modified.email)
        assertEquals(original.password, modified.password)
    }

    @Test
    fun `should have proper equals and hashCode`() {
        // Given
        val request1 =
            TestDataFactory.createSignupRequest(
                email = "test@example.com",
                password = "password",
                username = "user",
            )
        val request2 =
            TestDataFactory.createSignupRequest(
                email = "test@example.com",
                password = "password",
                username = "user",
            )
        val request3 =
            TestDataFactory.createSignupRequest(
                email = "different@example.com",
                password = "password",
                username = "user",
            )

        // Then
        assertEquals(request1, request2)
        assertEquals(request1.hashCode(), request2.hashCode())
        assertTrue(request1 != request3)
    }

    @Test
    fun `should validate strong passwords`() {
        // Given
        val strongPasswords =
            listOf(
                "StrongPassword123!",
                "MySecureP@ss1",
                "Complex#Password99",
                "Anotherv3ry\$trongP@ssword",
            )

        strongPasswords.forEach { password ->
            // When
            val signupRequest =
                SignupRequest(
                    email = "test@example.com",
                    password = password,
                    username = "testuser",
                )
            val violations = validator.validate(signupRequest)

            // Then
            assertTrue(
                violations.isEmpty() || violations.none { it.propertyPath.toString() == "password" },
                "Password '$password' should be considered strong enough",
            )
        }
    }
}
