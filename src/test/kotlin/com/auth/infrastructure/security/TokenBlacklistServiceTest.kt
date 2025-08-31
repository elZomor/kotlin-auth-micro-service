package com.auth.infrastructure.security

import io.mockk.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.util.*
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class TokenBlacklistServiceTest {

    private lateinit var tokenBlacklistService: TokenBlacklistService
    private val jwtService = mockk<JwtService>()

    @BeforeEach
    fun setup() {
        clearAllMocks()
        tokenBlacklistService = TokenBlacklistService()
    }

    @Test
    fun `blacklistToken should add token to blacklist with expiration time`() {
        // Given
        val token = "valid.jwt.token"
        val expirationTime = System.currentTimeMillis() + 3600000 // 1 hour from now
        val mockClaims = mockk<io.jsonwebtoken.Jws<io.jsonwebtoken.Claims>>()
        val mockPayload = mockk<io.jsonwebtoken.Claims>()
        val mockExpiration = Date(expirationTime)

        every { jwtService.parse(token) } returns mockClaims
        every { mockClaims.payload } returns mockPayload
        every { mockPayload.expiration } returns mockExpiration

        // When
        tokenBlacklistService.blacklistToken(token, jwtService)

        // Then
        assertTrue(tokenBlacklistService.isTokenBlacklisted(token))
        verify { jwtService.parse(token) }
    }

    @Test
    fun `blacklistToken should handle invalid token gracefully`() {
        // Given
        val invalidToken = "invalid.jwt.token"

        every { jwtService.parse(invalidToken) } throws RuntimeException("Invalid token")

        // When
        tokenBlacklistService.blacklistToken(invalidToken, jwtService)

        // Then
        assertFalse(tokenBlacklistService.isTokenBlacklisted(invalidToken))
        verify { jwtService.parse(invalidToken) }
    }

    @Test
    fun `isTokenBlacklisted should return true for blacklisted token`() {
        // Given
        val token = "blacklisted.jwt.token"
        val expirationTime = System.currentTimeMillis() + 3600000 // 1 hour from now
        val mockClaims = mockk<io.jsonwebtoken.Jws<io.jsonwebtoken.Claims>>()
        val mockPayload = mockk<io.jsonwebtoken.Claims>()
        val mockExpiration = Date(expirationTime)

        every { jwtService.parse(token) } returns mockClaims
        every { mockClaims.payload } returns mockPayload
        every { mockPayload.expiration } returns mockExpiration

        // Blacklist the token first
        tokenBlacklistService.blacklistToken(token, jwtService)

        // When
        val result = tokenBlacklistService.isTokenBlacklisted(token)

        // Then
        assertTrue(result)
    }

    @Test
    fun `isTokenBlacklisted should return false for non-blacklisted token`() {
        // Given
        val token = "non.blacklisted.token"

        // When
        val result = tokenBlacklistService.isTokenBlacklisted(token)

        // Then
        assertFalse(result)
    }

    @Test
    fun `isTokenBlacklisted should return false and remove expired blacklisted token`() {
        // Given
        val token = "expired.blacklisted.token"
        val pastExpirationTime = System.currentTimeMillis() - 1000 // 1 second ago
        val mockClaims = mockk<io.jsonwebtoken.Jws<io.jsonwebtoken.Claims>>()
        val mockPayload = mockk<io.jsonwebtoken.Claims>()
        val mockExpiration = Date(pastExpirationTime)

        every { jwtService.parse(token) } returns mockClaims
        every { mockClaims.payload } returns mockPayload
        every { mockPayload.expiration } returns mockExpiration

        // Blacklist the token first
        tokenBlacklistService.blacklistToken(token, jwtService)

        // When
        val result = tokenBlacklistService.isTokenBlacklisted(token)

        // Then
        assertFalse(result)
        
        // Verify token was removed from blacklist
        val secondResult = tokenBlacklistService.isTokenBlacklisted(token)
        assertFalse(secondResult)
    }

    @Test
    fun `cleanupExpiredTokens should remove expired tokens from blacklist`() {
        // Given
        val validToken = "valid.token"
        val expiredToken1 = "expired.token.1"
        val expiredToken2 = "expired.token.2"
        
        val futureTime = System.currentTimeMillis() + 3600000 // 1 hour from now
        val pastTime = System.currentTimeMillis() - 1000 // 1 second ago
        
        // Setup valid token
        val validClaims = mockk<io.jsonwebtoken.Jws<io.jsonwebtoken.Claims>>()
        val validPayload = mockk<io.jsonwebtoken.Claims>()
        every { jwtService.parse(validToken) } returns validClaims
        every { validClaims.payload } returns validPayload
        every { validPayload.expiration } returns Date(futureTime)
        
        // Setup expired tokens
        val expiredClaims1 = mockk<io.jsonwebtoken.Jws<io.jsonwebtoken.Claims>>()
        val expiredPayload1 = mockk<io.jsonwebtoken.Claims>()
        every { jwtService.parse(expiredToken1) } returns expiredClaims1
        every { expiredClaims1.payload } returns expiredPayload1
        every { expiredPayload1.expiration } returns Date(pastTime)
        
        val expiredClaims2 = mockk<io.jsonwebtoken.Jws<io.jsonwebtoken.Claims>>()
        val expiredPayload2 = mockk<io.jsonwebtoken.Claims>()
        every { jwtService.parse(expiredToken2) } returns expiredClaims2
        every { expiredClaims2.payload } returns expiredPayload2
        every { expiredPayload2.expiration } returns Date(pastTime)

        // Blacklist all tokens
        tokenBlacklistService.blacklistToken(validToken, jwtService)
        tokenBlacklistService.blacklistToken(expiredToken1, jwtService)
        tokenBlacklistService.blacklistToken(expiredToken2, jwtService)

        // When
        tokenBlacklistService.cleanupExpiredTokens()

        // Then
        assertTrue(tokenBlacklistService.isTokenBlacklisted(validToken)) // Should still be blacklisted
        assertFalse(tokenBlacklistService.isTokenBlacklisted(expiredToken1)) // Should be removed
        assertFalse(tokenBlacklistService.isTokenBlacklisted(expiredToken2)) // Should be removed
    }

    @Test
    fun `cleanupExpiredTokens should handle empty blacklist`() {
        // When & Then (should not throw exception)
        tokenBlacklistService.cleanupExpiredTokens()
    }

    @Test
    fun `cleanupExpiredTokens should handle blacklist with no expired tokens`() {
        // Given
        val token = "valid.token"
        val futureTime = System.currentTimeMillis() + 3600000 // 1 hour from now
        
        val mockClaims = mockk<io.jsonwebtoken.Jws<io.jsonwebtoken.Claims>>()
        val mockPayload = mockk<io.jsonwebtoken.Claims>()
        every { jwtService.parse(token) } returns mockClaims
        every { mockClaims.payload } returns mockPayload
        every { mockPayload.expiration } returns Date(futureTime)

        tokenBlacklistService.blacklistToken(token, jwtService)

        // When
        tokenBlacklistService.cleanupExpiredTokens()

        // Then
        assertTrue(tokenBlacklistService.isTokenBlacklisted(token)) // Should still be blacklisted
    }

    @Test
    fun `multiple tokens can be blacklisted independently`() {
        // Given
        val token1 = "token.1"
        val token2 = "token.2"
        val token3 = "token.3"
        val futureTime = System.currentTimeMillis() + 3600000
        
        listOf(token1, token2, token3).forEach { token ->
            val mockClaims = mockk<io.jsonwebtoken.Jws<io.jsonwebtoken.Claims>>()
            val mockPayload = mockk<io.jsonwebtoken.Claims>()
            every { jwtService.parse(token) } returns mockClaims
            every { mockClaims.payload } returns mockPayload
            every { mockPayload.expiration } returns Date(futureTime)
        }

        // When
        tokenBlacklistService.blacklistToken(token1, jwtService)
        tokenBlacklistService.blacklistToken(token2, jwtService)

        // Then
        assertTrue(tokenBlacklistService.isTokenBlacklisted(token1))
        assertTrue(tokenBlacklistService.isTokenBlacklisted(token2))
        assertFalse(tokenBlacklistService.isTokenBlacklisted(token3)) // Not blacklisted
    }
}