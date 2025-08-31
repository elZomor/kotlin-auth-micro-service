package com.auth.presentation.filter

import com.auth.infrastructure.security.AppUserDetailsService
import com.auth.infrastructure.security.JwtService
import com.auth.infrastructure.security.TokenBlacklistService
import io.mockk.Runs
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.verify
import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.security.core.context.SecurityContextHolder
import kotlin.test.assertNull

class JwtAuthFilterTest {
    private val jwtService = mockk<JwtService>(relaxed = true)
    private val     appUserDetailsService = mockk<AppUserDetailsService>(relaxed = true)
    private val tokenBlacklistService = mockk<TokenBlacklistService>(relaxed = true)
    private val request = mockk<HttpServletRequest>(relaxed = true)
    private val response = mockk<HttpServletResponse>(relaxed = true)
    private val filterChain = mockk<FilterChain>(relaxed = true)

    private lateinit var jwtAuthFilter: JwtAuthFilter

    @BeforeEach
    fun setup() {
        clearAllMocks()
        SecurityContextHolder.clearContext()
        jwtAuthFilter = JwtAuthFilter(jwtService, appUserDetailsService, tokenBlacklistService)

        // Default mock behaviors
        every { filterChain.doFilter(request, response) } just Runs
    }

    @Test
    fun `should continue filter chain when no authorization header`() {
        // Given
        every { request.getHeader("Authorization") } returns null

        // When
        jwtAuthFilter.doFilterInternal(request, response, filterChain)

        // Then
        verify { filterChain.doFilter(request, response) }
        assertNull(SecurityContextHolder.getContext().authentication)
    }

    @Test
    fun `should continue filter chain when authorization header does not start with Bearer`() {
        // Given
        every { request.getHeader("Authorization") } returns "Basic sometoken"

        // When
        jwtAuthFilter.doFilterInternal(request, response, filterChain)

        // Then
        verify { filterChain.doFilter(request, response) }
        assertNull(SecurityContextHolder.getContext().authentication)
    }

    @Test
    fun `should continue filter chain when token is blacklisted`() {
        // Given
        val token = "valid.jwt.token"
        every { request.getHeader("Authorization") } returns "Bearer $token"
        every { tokenBlacklistService.isTokenBlacklisted(token) } returns true

        // When
        jwtAuthFilter.doFilterInternal(request, response, filterChain)

        // Then
        verify { tokenBlacklistService.isTokenBlacklisted(token) }
        verify { filterChain.doFilter(request, response) }
        assertNull(SecurityContextHolder.getContext().authentication)
    }

    @Test
    fun `should continue filter chain when token parsing fails`() {
        // Given
        val token = "invalid.jwt.token"
        every { request.getHeader("Authorization") } returns "Bearer $token"
        every { tokenBlacklistService.isTokenBlacklisted(token) } returns false
        every { jwtService.parse(token) } throws RuntimeException("Invalid token")

        // When
        jwtAuthFilter.doFilterInternal(request, response, filterChain)

        // Then
        verify { tokenBlacklistService.isTokenBlacklisted(token) }
        verify { jwtService.parse(token) }
        verify { filterChain.doFilter(request, response) }
        assertNull(SecurityContextHolder.getContext().authentication)
    }

    @Test
    fun `should set authentication when token is valid`() {
        // Given
        val token = "valid.jwt.token"
        val mockClaims = mockk<io.jsonwebtoken.Jws<io.jsonwebtoken.Claims>>()
        val mockPayload = mockk<io.jsonwebtoken.Claims>()
        val authorities = listOf("ROLE_USER", "READ_USER")
        val mockUserDetails = mockk<org.springframework.security.core.userdetails.UserDetails>()

        every { request.getHeader("Authorization") } returns "Bearer $token"
        every { tokenBlacklistService.isTokenBlacklisted(token) } returns false
        every { jwtService.parse(token) } returns mockClaims
        every { mockClaims.payload } returns mockPayload
        every { mockPayload.subject } returns "test@example.com"
        every { mockPayload["authorities"] } returns authorities
        every { appUserDetailsService.loadUserByUsername("test@example.com") } returns mockUserDetails
        every { mockUserDetails.authorities } returns authorities.map { org.springframework.security.core.authority.SimpleGrantedAuthority(it) }
        every { mockUserDetails.username } returns "test@example.com"

        // When
        jwtAuthFilter.doFilterInternal(request, response, filterChain)

        // Then
        verify { tokenBlacklistService.isTokenBlacklisted(token) }
        verify { jwtService.parse(token) }
        verify { appUserDetailsService.loadUserByUsername("test@example.com") }
        verify { filterChain.doFilter(request, response) }

        // Verify authentication was set
        val authentication = SecurityContextHolder.getContext().authentication
        kotlin.test.assertNotNull(authentication)
        kotlin.test.assertEquals("test@example.com", authentication.name)
        kotlin.test.assertEquals(2, authentication.authorities.size)
    }

    @Test
    fun `should handle empty authorities list`() {
        // Given
        val token = "valid.jwt.token"
        val mockClaims = mockk<io.jsonwebtoken.Jws<io.jsonwebtoken.Claims>>()
        val mockPayload = mockk<io.jsonwebtoken.Claims>()
        val authorities = emptyList<String>()
        val mockUserDetails = mockk<org.springframework.security.core.userdetails.UserDetails>()

        every { request.getHeader("Authorization") } returns "Bearer $token"
        every { tokenBlacklistService.isTokenBlacklisted(token) } returns false
        every { jwtService.parse(token) } returns mockClaims
        every { mockClaims.payload } returns mockPayload
        every { mockPayload.subject } returns "test@example.com"
        every { mockPayload["authorities"] } returns authorities
        every { appUserDetailsService.loadUserByUsername("test@example.com") } returns mockUserDetails
        every { mockUserDetails.authorities } returns emptyList()
        every { mockUserDetails.username } returns "test@example.com"

        // When
        jwtAuthFilter.doFilterInternal(request, response, filterChain)

        // Then
        verify { filterChain.doFilter(request, response) }

        val authentication = SecurityContextHolder.getContext().authentication
        kotlin.test.assertNotNull(authentication)
        kotlin.test.assertEquals("test@example.com", authentication.name)
        kotlin.test.assertEquals(0, authentication.authorities.size)
    }

    @Test
    fun `should handle null authorities in token`() {
        // Given
        val token = "valid.jwt.token"
        val mockClaims = mockk<io.jsonwebtoken.Jws<io.jsonwebtoken.Claims>>()
        val mockPayload = mockk<io.jsonwebtoken.Claims>()
        val mockUserDetails = mockk<org.springframework.security.core.userdetails.UserDetails>()

        every { request.getHeader("Authorization") } returns "Bearer $token"
        every { tokenBlacklistService.isTokenBlacklisted(token) } returns false
        every { jwtService.parse(token) } returns mockClaims
        every { mockClaims.payload } returns mockPayload
        every { mockPayload.subject } returns "test@example.com"
        every { mockPayload["authorities"] } returns null
        every { appUserDetailsService.loadUserByUsername("test@example.com") } returns mockUserDetails
        every { mockUserDetails.authorities } returns emptyList()
        every { mockUserDetails.username } returns "test@example.com"

        // When
        jwtAuthFilter.doFilterInternal(request, response, filterChain)

        // Then
        verify { filterChain.doFilter(request, response) }

        val authentication = SecurityContextHolder.getContext().authentication
        kotlin.test.assertNotNull(authentication)
        kotlin.test.assertEquals("test@example.com", authentication.name)
        kotlin.test.assertEquals(0, authentication.authorities.size)
    }

    @Test
    fun `should trim Bearer prefix correctly`() {
        // Given
        val token = "valid.jwt.token"
        val authHeader = "Bearer $token"
        val mockClaims = mockk<io.jsonwebtoken.Jws<io.jsonwebtoken.Claims>>()
        val mockPayload = mockk<io.jsonwebtoken.Claims>()
        val mockUserDetails = mockk<org.springframework.security.core.userdetails.UserDetails>()

        every { request.getHeader("Authorization") } returns authHeader
        every { tokenBlacklistService.isTokenBlacklisted(token) } returns false
        every { jwtService.parse(token) } returns mockClaims
        every { mockClaims.payload } returns mockPayload
        every { mockPayload.subject } returns "test@example.com"
        every { mockPayload["authorities"] } returns listOf("ROLE_USER")
        every { appUserDetailsService.loadUserByUsername("test@example.com") } returns mockUserDetails
        every { mockUserDetails.authorities } returns listOf(org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_USER"))
        every { mockUserDetails.username } returns "test@example.com"

        // When
        jwtAuthFilter.doFilterInternal(request, response, filterChain)

        // Then
        verify { tokenBlacklistService.isTokenBlacklisted(token) } // Should use token without "Bearer " prefix
        verify { jwtService.parse(token) } // Should use token without "Bearer " prefix
    }

    @Test
    fun `should handle bearer with different case`() {
        // Given
        every { request.getHeader("Authorization") } returns "bearer token"

        // When
        jwtAuthFilter.doFilterInternal(request, response, filterChain)

        // Then
        verify { filterChain.doFilter(request, response) }
        assertNull(SecurityContextHolder.getContext().authentication)
        // Should not process tokens that don't start with exact "Bearer " (case sensitive)
    }
}
