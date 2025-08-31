package com.auth.presentation.controller

import com.auth.common.TestDataFactory
import com.auth.domain.service.UserService
import com.auth.infrastructure.security.JwtService
import com.auth.infrastructure.security.TokenBlacklistService
import com.auth.presentation.dto.LoginRequest
import com.auth.presentation.dto.SignupRequest
import com.auth.presentation.dto.RefreshTokenRequest
import com.auth.presentation.dto.UpdateUsernameRequest
import com.fasterxml.jackson.databind.ObjectMapper
import io.mockk.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest
import org.springframework.boot.test.mock.mockito.MockBean
import org.springframework.http.MediaType
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.context.SecurityContext
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.*
import org.springframework.test.web.servlet.setup.MockMvcBuilders
import java.util.*

class AuthControllerTest {

    private val authenticationManager = mockk<AuthenticationManager>()
    private val jwtService = mockk<JwtService>()
    private val userService = mockk<UserService>()
    private val passwordEncoder = mockk<PasswordEncoder>()
    private val tokenBlacklistService = mockk<TokenBlacklistService>()
    
    private lateinit var authController: AuthController
    private lateinit var mockMvc: MockMvc
    private val objectMapper = ObjectMapper()

    @BeforeEach
    fun setup() {
        clearAllMocks()
        authController = AuthController(
            authenticationManager,
            jwtService,
            userService,
            passwordEncoder,
            tokenBlacklistService
        )
        mockMvc = MockMvcBuilders.standaloneSetup(authController).build()
    }

    @Test
    fun `login should return token response for valid credentials`() {
        // Given
        val loginRequest = TestDataFactory.createLoginRequest(
            email = "test@example.com",
            password = "password123"
        )
        val authentication = mockk<Authentication>()
        val authorities = listOf(SimpleGrantedAuthority("ROLE_USER"))
        
        every { authenticationManager.authenticate(any()) } returns authentication
        every { authentication.authorities } returns authorities
        every { jwtService.generate(loginRequest.email, listOf("ROLE_USER"), 3600) } returns "access-token"
        every { jwtService.generateRefreshToken(loginRequest.email) } returns "refresh-token"

        // When & Then
        mockMvc.perform(
            post("/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginRequest))
        )
        .andExpect(status().isOk)
        .andExpect(jsonPath("$.accessToken").value("access-token"))
        .andExpect(jsonPath("$.refreshToken").value("refresh-token"))
        .andExpect(jsonPath("$.type").value("Bearer"))
        .andExpect(jsonPath("$.expiresIn").value(3600))

        verify { authenticationManager.authenticate(any()) }
        verify { jwtService.generate(loginRequest.email, listOf("ROLE_USER"), 3600) }
        verify { jwtService.generateRefreshToken(loginRequest.email) }
    }

    @Test
    fun `login should return unauthorized for invalid credentials`() {
        // Given
        val loginRequest = TestDataFactory.createLoginRequest()
        
        every { authenticationManager.authenticate(any()) } throws BadCredentialsException("Invalid credentials")

        // When & Then
        mockMvc.perform(
            post("/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginRequest))
        )
        .andExpect(status().isUnauthorized)

        verify { authenticationManager.authenticate(any()) }
        verify(exactly = 0) { jwtService.generate(any(), any(), any()) }
    }

    @Test
    fun `signup should create user and return token response`() {
        // Given
        val signupRequest = TestDataFactory.createSignupRequest(
            email = "newuser@example.com",
            password = "password123",
            username = "newuser"
        )
        val createdUser = TestDataFactory.createUser(
            email = signupRequest.email,
            username = signupRequest.username
        )
        val authentication = mockk<Authentication>()
        val authorities = listOf(SimpleGrantedAuthority("ROLE_USER"))

        every { userService.createUser(signupRequest.email, signupRequest.password, signupRequest.username) } returns createdUser
        every { authenticationManager.authenticate(any()) } returns authentication
        every { authentication.authorities } returns authorities
        every { jwtService.generate(signupRequest.email, listOf("ROLE_USER"), 3600) } returns "access-token"
        every { jwtService.generateRefreshToken(signupRequest.email) } returns "refresh-token"

        // When & Then
        mockMvc.perform(
            post("/auth/signup")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(signupRequest))
        )
        .andExpect(status().isOk)
        .andExpect(jsonPath("$.accessToken").value("access-token"))
        .andExpect(jsonPath("$.refreshToken").value("refresh-token"))
        .andExpect(jsonPath("$.type").value("Bearer"))

        verify { userService.createUser(signupRequest.email, signupRequest.password, signupRequest.username) }
        verify { authenticationManager.authenticate(any()) }
    }

    @Test
    fun `signup should return bad request when user creation fails`() {
        // Given
        val signupRequest = TestDataFactory.createSignupRequest()
        
        every { userService.createUser(any(), any(), any()) } throws IllegalArgumentException("Email already exists")

        // When & Then
        mockMvc.perform(
            post("/auth/signup")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(signupRequest))
        )
        .andExpect(status().isBadRequest)

        verify { userService.createUser(signupRequest.email, signupRequest.password, signupRequest.username) }
        verify(exactly = 0) { authenticationManager.authenticate(any()) }
    }

    @Test
    fun `refresh should return new tokens for valid refresh token`() {
        // Given
        val refreshRequest = TestDataFactory.createRefreshTokenRequest("valid-refresh-token")
        val authorities = listOf("ROLE_USER")
        
        every { jwtService.isRefreshToken("valid-refresh-token") } returns true
        every { tokenBlacklistService.isTokenBlacklisted("valid-refresh-token") } returns false
        every { jwtService.generateAccessTokenFromRefreshToken("valid-refresh-token", authorities) } returns "new-access-token"
        every { jwtService.generateRefreshToken("test@example.com") } returns "new-refresh-token"
        
        val mockClaims = mockk<io.jsonwebtoken.Jws<io.jsonwebtoken.Claims>>()
        val mockPayload = mockk<io.jsonwebtoken.Claims>()
        every { jwtService.parse("valid-refresh-token") } returns mockClaims
        every { mockClaims.payload } returns mockPayload
        every { mockPayload.subject } returns "test@example.com"

        val user = TestDataFactory.createUser(email = "test@example.com")
        every { userService.byEmail("test@example.com") } returns Optional.of(user)
        every { userService.permissionsOf(user) } returns setOf("ROLE_USER")

        // When & Then
        mockMvc.perform(
            post("/auth/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(refreshRequest))
        )
        .andExpect(status().isOk)
        .andExpect(jsonPath("$.accessToken").value("new-access-token"))
        .andExpect(jsonPath("$.refreshToken").value("new-refresh-token"))

        verify { jwtService.isRefreshToken("valid-refresh-token") }
        verify { tokenBlacklistService.isTokenBlacklisted("valid-refresh-token") }
    }

    @Test
    fun `refresh should return unauthorized for invalid refresh token`() {
        // Given
        val refreshRequest = TestDataFactory.createRefreshTokenRequest("invalid-refresh-token")
        
        every { jwtService.isRefreshToken("invalid-refresh-token") } returns false

        // When & Then
        mockMvc.perform(
            post("/auth/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(refreshRequest))
        )
        .andExpect(status().isUnauthorized)

        verify { jwtService.isRefreshToken("invalid-refresh-token") }
        verify(exactly = 0) { jwtService.generateAccessTokenFromRefreshToken(any(), any()) }
    }

    @Test
    fun `refresh should return unauthorized for blacklisted token`() {
        // Given
        val refreshRequest = TestDataFactory.createRefreshTokenRequest("blacklisted-token")
        
        every { jwtService.isRefreshToken("blacklisted-token") } returns true
        every { tokenBlacklistService.isTokenBlacklisted("blacklisted-token") } returns true

        // When & Then
        mockMvc.perform(
            post("/auth/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(refreshRequest))
        )
        .andExpect(status().isUnauthorized)

        verify { jwtService.isRefreshToken("blacklisted-token") }
        verify { tokenBlacklistService.isTokenBlacklisted("blacklisted-token") }
    }

    @Test
    fun `logout should blacklist token and return success`() {
        // Given
        val token = "Bearer valid-token"
        
        every { tokenBlacklistService.blacklistToken("valid-token", jwtService) } just Runs

        // When & Then
        mockMvc.perform(
            post("/auth/logout")
                .header("Authorization", token)
        )
        .andExpect(status().isOk)

        verify { tokenBlacklistService.blacklistToken("valid-token", jwtService) }
    }

    @Test
    fun `logout should return bad request for missing authorization header`() {
        // When & Then
        mockMvc.perform(post("/auth/logout"))
        .andExpect(status().isBadRequest)

        verify(exactly = 0) { tokenBlacklistService.blacklistToken(any(), any()) }
    }

    @Test
    fun `updateUsername should update username for authenticated user`() {
        // Given
        val updateRequest = TestDataFactory.createUpdateUsernameRequest("newusername")
        val mockSecurityContext = mockk<SecurityContext>()
        val mockAuthentication = mockk<Authentication>()
        val updatedUser = TestDataFactory.createUser(
            email = "test@example.com",
            username = "newusername"
        )

        SecurityContextHolder.setContext(mockSecurityContext)
        every { mockSecurityContext.authentication } returns mockAuthentication
        every { mockAuthentication.name } returns "test@example.com"
        every { userService.updateUsername("test@example.com", "newusername") } returns updatedUser

        // When & Then
        mockMvc.perform(
            put("/auth/username")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(updateRequest))
        )
        .andExpect(status().isOk)
        .andExpect(jsonPath("$.username").value("newusername"))

        verify { userService.updateUsername("test@example.com", "newusername") }
    }

    @Test
    fun `login should return bad request for invalid input`() {
        // Given
        val invalidRequest = LoginRequest(email = "", password = "")

        // When & Then
        mockMvc.perform(
            post("/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(invalidRequest))
        )
        .andExpect(status().isBadRequest)

        verify(exactly = 0) { authenticationManager.authenticate(any()) }
    }

    @Test
    fun `signup should return bad request for invalid input`() {
        // Given
        val invalidRequest = SignupRequest(email = "invalid", password = "", username = null)

        // When & Then
        mockMvc.perform(
            post("/auth/signup")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(invalidRequest))
        )
        .andExpect(status().isBadRequest)

        verify(exactly = 0) { userService.createUser(any(), any(), any()) }
    }
}