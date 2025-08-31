package com.auth.common

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertDoesNotThrow
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class BcryptTestTest {

    @Test
    fun `main should execute without throwing exceptions`() {
        // When & Then
        assertDoesNotThrow {
            BcryptTest.main(emptyArray())
        }
    }

    @Test
    fun `should demonstrate bcrypt functionality`() {
        // Given
        val encoder = BCryptPasswordEncoder(4) // Lower cost for tests
        val password = "TestPassword123"

        // When
        val hash = encoder.encode(password)

        // Then
        assertTrue(encoder.matches(password, hash))
        assertFalse(encoder.matches("WrongPassword", hash))
    }

    @Test
    fun `should handle various password variations`() {
        // Given
        val encoder = BCryptPasswordEncoder(4)
        val basePassword = "Admin@123"
        val hash = encoder.encode(basePassword)
        
        val variations = listOf(
            "admin@123",    // Different case
            "Admin@123",    // Same
            "ADMIN@123",    // All caps
            "Admin123",     // No special char
            "admin123",     // Different case, no special char
            "Admin@123!",   // Extra special char
            "Admin@123#"    // Different special char
        )

        // When & Then
        variations.forEach { variation ->
            val matches = encoder.matches(variation, hash)
            if (variation == basePassword) {
                assertTrue(matches, "Original password should match")
            } else {
                assertFalse(matches, "Variation '$variation' should not match original")
            }
        }
    }

    @Test
    fun `should generate different hashes for same password`() {
        // Given
        val encoder = BCryptPasswordEncoder(4)
        val password = "SamePassword"

        // When
        val hash1 = encoder.encode(password)
        val hash2 = encoder.encode(password)

        // Then
        assertTrue(hash1 != hash2, "BCrypt should generate different hashes for same password")
        assertTrue(encoder.matches(password, hash1))
        assertTrue(encoder.matches(password, hash2))
    }

    @Test
    fun `should handle empty and special passwords`() {
        // Given
        val encoder = BCryptPasswordEncoder(4)
        val specialPasswords = listOf(
            "",                    // Empty
            " ",                   // Single space
            "   ",                 // Multiple spaces
            "!@#$%^&*()",         // Only special characters
            "123456789",          // Only numbers
            "abcdefghijklmnop",   // Only lowercase letters
            "ABCDEFGHIJKLMNOP",   // Only uppercase letters
            "日本語パスワード",        // Unicode characters
            "\n\t\r",             // Control characters
            "a".repeat(100)       // Very long password
        )

        // When & Then
        specialPasswords.forEach { password ->
            assertDoesNotThrow("Should handle password: '$password'") {
                val hash = encoder.encode(password)
                assertTrue(encoder.matches(password, hash))
            }
        }
    }
}