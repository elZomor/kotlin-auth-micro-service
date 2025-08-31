package com.auth.infrastructure.security

import io.jsonwebtoken.ExpiredJwtException
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class JwtServiceTest {
    private lateinit var jwtService: JwtService
    private val testSecret = "test-secret-key-that-is-very-long-and-secure-for-testing-purposes-only"
    private val testIssuer = "test-issuer"

    @BeforeEach
    fun setup() {
        jwtService = JwtService(testSecret, testIssuer)
    }

    @Test
    fun `generate should create valid JWT token`() {
        // Given
        val subject = "test@example.com"
        val authorities = listOf("ROLE_USER", "READ_USER")
        val ttlSeconds = 3600L

        // When
        val token = jwtService.generate(subject, authorities, ttlSeconds)

        // Then
        assertNotNull(token)
        assertTrue(token.isNotBlank())

        // Verify token can be parsed
        val claims = jwtService.parse(token)
        assertEquals(subject, claims.payload.subject)
        assertEquals(testIssuer, claims.payload.issuer)
        assertEquals(authorities, claims.payload["authorities"])
        assertNotNull(claims.payload.id)
        assertNotNull(claims.payload.issuedAt)
        assertNotNull(claims.payload.expiration)
    }

    @Test
    fun `parse should extract claims from valid token`() {
        // Given
        val subject = "test@example.com"
        val authorities = listOf("ROLE_ADMIN")
        val ttlSeconds = 3600L
        val token = jwtService.generate(subject, authorities, ttlSeconds)

        // When
        val claims = jwtService.parse(token)

        // Then
        assertEquals(subject, claims.payload.subject)
        assertEquals(testIssuer, claims.payload.issuer)
        assertEquals(authorities, claims.payload["authorities"])
        assertTrue(claims.payload.expiration.time > System.currentTimeMillis())
    }

    @Test
    fun `parse should throw exception for invalid token`() {
        // Given
        val invalidToken = "invalid.jwt.token"

        // When & Then
        assertThrows<Exception> {
            jwtService.parse(invalidToken)
        }
    }

    @Test
    fun `parse should throw exception for expired token`() {
        // Given
        val subject = "test@example.com"
        val authorities = listOf("ROLE_USER")
        val expiredTtl = -1L // Already expired
        val expiredToken = jwtService.generate(subject, authorities, expiredTtl)

        // When & Then
        assertThrows<ExpiredJwtException> {
            jwtService.parse(expiredToken)
        }
    }

    @Test
    fun `generateRefreshToken should create refresh token`() {
        // Given
        val subject = "test@example.com"
        val ttlSeconds = 7 * 24 * 3600L // 7 days

        // When
        val refreshToken = jwtService.generateRefreshToken(subject, ttlSeconds)

        // Then
        assertNotNull(refreshToken)
        assertTrue(refreshToken.isNotBlank())

        // Verify refresh token properties
        val claims = jwtService.parse(refreshToken)
        assertEquals(subject, claims.payload.subject)
        assertEquals(testIssuer, claims.payload.issuer)
        assertEquals("refresh", claims.payload["type"])
        assertNotNull(claims.payload.id)
    }

    @Test
    fun `generateRefreshToken should use default TTL when not specified`() {
        // Given
        val subject = "test@example.com"

        // When
        val refreshToken = jwtService.generateRefreshToken(subject)

        // Then
        assertNotNull(refreshToken)
        val claims = jwtService.parse(refreshToken)
        assertEquals("refresh", claims.payload["type"])

        // Check that expiration is approximately 7 days from now
        val expectedExpiration = System.currentTimeMillis() + (7 * 24 * 3600 * 1000L)
        val actualExpiration = claims.payload.expiration.time
        val timeDifference = Math.abs(expectedExpiration - actualExpiration)
        assertTrue(timeDifference < 60000) // Within 1 minute tolerance
    }

    @Test
    fun `generateAccessTokenFromRefreshToken should create access token from valid refresh token`() {
        // Given
        val subject = "test@example.com"
        val refreshToken = jwtService.generateRefreshToken(subject)
        val authorities = listOf("ROLE_USER", "READ_USER")
        val ttlSeconds = 3600L

        // When
        val accessToken = jwtService.generateAccessTokenFromRefreshToken(refreshToken, authorities, ttlSeconds)

        // Then
        assertNotNull(accessToken)
        val claims = jwtService.parse(accessToken)
        assertEquals(subject, claims.payload.subject)
        assertEquals(authorities, claims.payload["authorities"])
        // Should not have "type" claim (not a refresh token)
        assertEquals(null, claims.payload["type"])
    }

    @Test
    fun `generateAccessTokenFromRefreshToken should use default TTL`() {
        // Given
        val subject = "test@example.com"
        val refreshToken = jwtService.generateRefreshToken(subject)
        val authorities = listOf("ROLE_USER")

        // When
        val accessToken = jwtService.generateAccessTokenFromRefreshToken(refreshToken, authorities)

        // Then
        assertNotNull(accessToken)
        val claims = jwtService.parse(accessToken)

        // Check that expiration is approximately 1 hour from now
        val expectedExpiration = System.currentTimeMillis() + (3600 * 1000L)
        val actualExpiration = claims.payload.expiration.time
        val timeDifference = Math.abs(expectedExpiration - actualExpiration)
        assertTrue(timeDifference < 60000) // Within 1 minute tolerance
    }

    @Test
    fun `generateAccessTokenFromRefreshToken should throw exception for invalid refresh token type`() {
        // Given
        val subject = "test@example.com"
        val regularToken = jwtService.generate(subject, listOf("ROLE_USER"), 3600L) // Not a refresh token
        val authorities = listOf("ROLE_USER")

        // When & Then
        val exception =
            assertThrows<IllegalArgumentException> {
                jwtService.generateAccessTokenFromRefreshToken(regularToken, authorities)
            }

        assertEquals("Invalid refresh token type", exception.message)
    }

    @Test
    fun `isRefreshToken should return true for refresh tokens`() {
        // Given
        val subject = "test@example.com"
        val refreshToken = jwtService.generateRefreshToken(subject)

        // When
        val result = jwtService.isRefreshToken(refreshToken)

        // Then
        assertTrue(result)
    }

    @Test
    fun `isRefreshToken should return false for access tokens`() {
        // Given
        val subject = "test@example.com"
        val accessToken = jwtService.generate(subject, listOf("ROLE_USER"), 3600L)

        // When
        val result = jwtService.isRefreshToken(accessToken)

        // Then
        assertFalse(result)
    }

    @Test
    fun `isRefreshToken should return false for invalid tokens`() {
        // Given
        val invalidToken = "invalid.jwt.token"

        // When
        val result = jwtService.isRefreshToken(invalidToken)

        // Then
        assertFalse(result)
    }

    @Test
    fun `should handle empty authorities list`() {
        // Given
        val subject = "test@example.com"
        val emptyAuthorities = emptyList<String>()
        val ttlSeconds = 3600L

        // When
        val token = jwtService.generate(subject, emptyAuthorities, ttlSeconds)

        // Then
        assertNotNull(token)
        val claims = jwtService.parse(token)
        assertEquals(emptyAuthorities, claims.payload["authorities"])
    }

    @Test
    fun `should handle multiple authorities`() {
        // Given
        val subject = "test@example.com"
        val authorities = listOf("ROLE_USER", "ROLE_ADMIN", "READ_USER", "WRITE_USER", "DELETE_USER")
        val ttlSeconds = 3600L

        // When
        val token = jwtService.generate(subject, authorities, ttlSeconds)

        // Then
        assertNotNull(token)
        val claims = jwtService.parse(token)
        assertEquals(authorities, claims.payload["authorities"])
    }
}
