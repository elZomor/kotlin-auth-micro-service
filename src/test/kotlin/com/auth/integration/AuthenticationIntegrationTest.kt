package com.auth.integration

import com.auth.common.TestConfiguration
import com.auth.common.TestDataFactory
import com.auth.presentation.dto.LoginRequest
import com.auth.presentation.dto.SignupRequest
import com.fasterxml.jackson.databind.ObjectMapper
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureWebMvc
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.context.annotation.Import
import org.springframework.http.MediaType
import org.springframework.test.context.TestPropertySource
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.*
import org.springframework.transaction.annotation.Transactional

@SpringBootTest
@AutoConfigureWebMvc
@Import(TestConfiguration::class)
@TestPropertySource(properties = [
    "spring.datasource.url=jdbc:h2:mem:testdb",
    "spring.jpa.hibernate.ddl-auto=create-drop",
    "jwt.secret=test-secret-key-for-integration-testing-that-is-very-long",
    "jwt.issuer=integration-test"
])
@Transactional
class AuthenticationIntegrationTest {

    @Autowired
    private lateinit var mockMvc: MockMvc

    private val objectMapper = ObjectMapper()

    @Test
    fun `complete authentication flow should work end-to-end`() {
        // Given
        val signupRequest = TestDataFactory.createSignupRequest(
            email = "integration@example.com",
            password = "StrongPassword123!",
            username = "integrationuser"
        )

        // Step 1: Sign up a new user
        val signupResult = mockMvc.perform(
            post("/auth/signup")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(signupRequest))
        )
        .andExpect(status().isOk)
        .andExpect(jsonPath("$.accessToken").exists())
        .andExpect(jsonPath("$.refreshToken").exists())
        .andExpect(jsonPath("$.type").value("Bearer"))
        .andReturn()

        val signupResponse = objectMapper.readTree(signupResult.response.contentAsString)
        val initialAccessToken = signupResponse["accessToken"].asText()
        val initialRefreshToken = signupResponse["refreshToken"].asText()

        // Step 2: Login with the same credentials
        val loginRequest = TestDataFactory.createLoginRequest(
            email = signupRequest.email,
            password = signupRequest.password
        )

        mockMvc.perform(
            post("/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginRequest))
        )
        .andExpect(status().isOk)
        .andExpect(jsonPath("$.accessToken").exists())
        .andExpect(jsonPath("$.refreshToken").exists())
        .andExpect(jsonPath("$.type").value("Bearer"))

        // Step 3: Access protected resource using access token
        mockMvc.perform(
            get("/auth/me")
                .header("Authorization", "Bearer $initialAccessToken")
        )
        .andExpect(status().isOk)

        // Step 4: Refresh tokens using refresh token
        val refreshRequest = mapOf("refreshToken" to initialRefreshToken)

        val refreshResult = mockMvc.perform(
            post("/auth/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(refreshRequest))
        )
        .andExpect(status().isOk)
        .andExpect(jsonPath("$.accessToken").exists())
        .andExpect(jsonPath("$.refreshToken").exists())
        .andReturn()

        val refreshResponse = objectMapper.readTree(refreshResult.response.contentAsString)
        val newAccessToken = refreshResponse["accessToken"].asText()

        // Step 5: Use new access token to access protected resource
        mockMvc.perform(
            get("/auth/me")
                .header("Authorization", "Bearer $newAccessToken")
        )
        .andExpect(status().isOk)

        // Step 6: Logout (blacklist current token)
        mockMvc.perform(
            post("/auth/logout")
                .header("Authorization", "Bearer $newAccessToken")
        )
        .andExpect(status().isOk)

        // Step 7: Verify that blacklisted token cannot access protected resources
        mockMvc.perform(
            get("/auth/me")
                .header("Authorization", "Bearer $newAccessToken")
        )
        .andExpect(status().isUnauthorized)
    }

    @Test
    fun `signup should fail for duplicate email`() {
        // Given
        val signupRequest = TestDataFactory.createSignupRequest(
            email = "duplicate@example.com",
            password = "StrongPassword123!",
            username = "user1"
        )

        // Step 1: First signup should succeed
        mockMvc.perform(
            post("/auth/signup")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(signupRequest))
        )
        .andExpect(status().isOk)

        // Step 2: Second signup with same email should fail
        val duplicateSignupRequest = signupRequest.copy(username = "user2")

        mockMvc.perform(
            post("/auth/signup")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(duplicateSignupRequest))
        )
        .andExpect(status().isBadRequest)
    }

    @Test
    fun `login should fail for non-existent user`() {
        // Given
        val loginRequest = TestDataFactory.createLoginRequest(
            email = "nonexistent@example.com",
            password = "password123"
        )

        // When & Then
        mockMvc.perform(
            post("/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginRequest))
        )
        .andExpect(status().isUnauthorized)
    }

    @Test
    fun `login should fail for wrong password`() {
        // Given
        val signupRequest = TestDataFactory.createSignupRequest(
            email = "wrongpass@example.com",
            password = "correctpassword",
            username = "user"
        )

        // Create user first
        mockMvc.perform(
            post("/auth/signup")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(signupRequest))
        )
        .andExpect(status().isOk)

        // Try to login with wrong password
        val loginRequest = TestDataFactory.createLoginRequest(
            email = signupRequest.email,
            password = "wrongpassword"
        )

        mockMvc.perform(
            post("/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginRequest))
        )
        .andExpect(status().isUnauthorized)
    }

    @Test
    fun `refresh should fail for invalid refresh token`() {
        // Given
        val invalidRefreshRequest = mapOf("refreshToken" to "invalid.refresh.token")

        // When & Then
        mockMvc.perform(
            post("/auth/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(invalidRefreshRequest))
        )
        .andExpect(status().isUnauthorized)
    }

    @Test
    fun `access protected resource should fail without token`() {
        // When & Then
        mockMvc.perform(get("/auth/me"))
        .andExpect(status().isUnauthorized)
    }

    @Test
    fun `access protected resource should fail with invalid token`() {
        // When & Then
        mockMvc.perform(
            get("/auth/me")
                .header("Authorization", "Bearer invalid.jwt.token")
        )
        .andExpect(status().isUnauthorized)
    }

    @Test
    fun `username update should work with valid token`() {
        // Given
        val signupRequest = TestDataFactory.createSignupRequest(
            email = "updatetest@example.com",
            password = "password123",
            username = "originaluser"
        )

        // Create user and get token
        val signupResult = mockMvc.perform(
            post("/auth/signup")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(signupRequest))
        )
        .andExpect(status().isOk)
        .andReturn()

        val response = objectMapper.readTree(signupResult.response.contentAsString)
        val accessToken = response["accessToken"].asText()

        // Update username
        val updateRequest = mapOf("username" to "updateduser")

        mockMvc.perform(
            put("/auth/username")
                .header("Authorization", "Bearer $accessToken")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(updateRequest))
        )
        .andExpect(status().isOk)
        .andExpect(jsonPath("$.username").value("updateduser"))
    }
}