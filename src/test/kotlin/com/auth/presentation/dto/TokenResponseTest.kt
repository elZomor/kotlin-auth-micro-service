package com.auth.presentation.dto

import com.auth.common.TestDataFactory
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class TokenResponseTest {
    @Test
    fun `should create token response with all fields`() {
        // Given & When
        val tokenResponse =
            TestDataFactory.createTokenResponse(
                accessToken = "access-token-123",
                refreshToken = "refresh-token-456",
                tokenType = "Bearer",
                expiresIn = 3600,
            )

        // Then
        assertEquals("access-token-123", tokenResponse.accessToken)
        assertEquals("refresh-token-456", tokenResponse.refreshToken)
        assertEquals("Bearer", tokenResponse.tokenType)
        assertEquals(3600, tokenResponse.expiresIn)
    }

    @Test
    fun `should create token response with default values`() {
        // Given & When
        val tokenResponse = TestDataFactory.createTokenResponse()

        // Then
        assertEquals("access-token", tokenResponse.accessToken)
        assertEquals("refresh-token", tokenResponse.refreshToken)
        assertEquals("Bearer", tokenResponse.tokenType)
        assertEquals(3600, tokenResponse.expiresIn)
    }

    @Test
    fun `should support data class operations`() {
        // Given
        val original = TestDataFactory.createTokenResponse(accessToken = "original-token")

        // When
        val modified = original.copy(accessToken = "new-token")

        // Then
        assertEquals("new-token", modified.accessToken)
        assertEquals(original.refreshToken, modified.refreshToken)
        assertEquals(original.tokenType, modified.tokenType)
        assertEquals(original.expiresIn, modified.expiresIn)
    }

    @Test
    fun `should have proper equals and hashCode`() {
        // Given
        val response1 =
            TestDataFactory.createTokenResponse(
                accessToken = "token123",
                refreshToken = "refresh123",
            )
        val response2 =
            TestDataFactory.createTokenResponse(
                accessToken = "token123",
                refreshToken = "refresh123",
            )
        val response3 =
            TestDataFactory.createTokenResponse(
                accessToken = "different-token",
                refreshToken = "refresh123",
            )

        // Then
        assertEquals(response1, response2)
        assertEquals(response1.hashCode(), response2.hashCode())
        assertTrue(response1 != response3)
    }

    @Test
    fun `should handle different token types`() {
        // Given
        val bearerResponse = TestDataFactory.createTokenResponse(tokenType = "Bearer")
        val basicResponse = TestDataFactory.createTokenResponse(tokenType = "Basic")
        val customResponse = TestDataFactory.createTokenResponse(tokenType = "Custom")

        // Then
        assertEquals("Bearer", bearerResponse.tokenType)
        assertEquals("Basic", basicResponse.tokenType)
        assertEquals("Custom", customResponse.tokenType)
    }

    @Test
    fun `should handle different expiration times`() {
        // Given
        val shortExpiry = TestDataFactory.createTokenResponse(expiresIn = 900) // 15 minutes
        val standardExpiry = TestDataFactory.createTokenResponse(expiresIn = 3600) // 1 hour
        val longExpiry = TestDataFactory.createTokenResponse(expiresIn = 86400) // 24 hours

        // Then
        assertEquals(900, shortExpiry.expiresIn)
        assertEquals(3600, standardExpiry.expiresIn)
        assertEquals(86400, longExpiry.expiresIn)
    }

    @Test
    fun `should handle long token strings`() {
        // Given
        val longAccessToken = "a".repeat(1000)
        val longRefreshToken = "b".repeat(1500)

        // When
        val tokenResponse =
            TestDataFactory.createTokenResponse(
                accessToken = longAccessToken,
                refreshToken = longRefreshToken,
            )

        // Then
        assertEquals(longAccessToken, tokenResponse.accessToken)
        assertEquals(longRefreshToken, tokenResponse.refreshToken)
        assertEquals(1000, tokenResponse.accessToken.length)
        assertEquals(1500, tokenResponse.refreshToken.length)
    }

    @Test
    fun `should have meaningful toString representation`() {
        // Given
        val tokenResponse =
            TestDataFactory.createTokenResponse(
                accessToken = "access123",
                refreshToken = "refresh456",
                tokenType = "Bearer",
                expiresIn = 3600,
            )

        // When
        val stringRepresentation = tokenResponse.toString()

        // Then
        assertTrue(stringRepresentation.contains("TokenResponse"))
        assertTrue(stringRepresentation.contains("Bearer"))
        assertTrue(stringRepresentation.contains("3600"))
        // Note: We might not want to include actual tokens in toString for security
    }

    @Test
    fun `should handle zero expiration time`() {
        // Given & When
        val tokenResponse = TestDataFactory.createTokenResponse(expiresIn = 0)

        // Then
        assertEquals(0, tokenResponse.expiresIn)
    }

    @Test
    fun `should handle negative expiration time`() {
        // Given & When
        val tokenResponse = TestDataFactory.createTokenResponse(expiresIn = -1)

        // Then
        assertEquals(-1, tokenResponse.expiresIn)
    }
}
