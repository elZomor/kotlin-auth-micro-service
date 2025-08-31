package com.auth.presentation.controller

import com.auth.domain.service.UserService
import com.auth.infrastructure.security.JwtService
import com.auth.infrastructure.security.TokenBlacklistService
import com.auth.presentation.dto.LoginRequest
import com.auth.presentation.dto.RefreshTokenRequest
import com.auth.presentation.dto.SignupRequest
import com.auth.presentation.dto.TokenResponse
import com.auth.presentation.dto.UpdateUsernameRequest
import jakarta.validation.Valid
import org.slf4j.LoggerFactory
import org.springframework.http.ResponseEntity
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.PutMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestHeader
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/auth")
class AuthController(
    private val am: AuthenticationManager,
    private val jwt: JwtService,
    private val userService: UserService,
    private val passwordEncoder: PasswordEncoder,
    private val tokenBlacklistService: TokenBlacklistService,
) {
    private val logger = LoggerFactory.getLogger(AuthController::class.java)

    @PostMapping("/signup")
    fun signup(
        @Valid @RequestBody body: SignupRequest,
    ): ResponseEntity<Map<String, Any>> {
        logger.info("Signup attempt for email: ${body.email}")
        try {
            // Create user
            val user = userService.createUser(body.email, body.password, body.username)
            logger.info("User created successfully: ${user.email}")

            // Generate tokens for immediate login
            val permissions = userService.permissionsOf(user)
            val accessToken = jwt.generate(user.email, permissions, 3600)
            val refreshToken = jwt.generateRefreshToken(user.email)

            logger.info("Signup and login successful for: ${body.email}")
            return ResponseEntity.ok(
                mapOf(
                    "accessToken" to accessToken,
                    "refreshToken" to refreshToken,
                    "tokenType" to "Bearer",
                    "expiresIn" to 3600,
                ),
            )
        } catch (e: IllegalArgumentException) {
            logger.error("Signup failed for ${body.email}: ${e.message}")
            return ResponseEntity.badRequest().body(mapOf("error" to "Illegal Argument: ${e.message}"))
        } catch (e: Exception) {
            logger.error("Signup failed for ${body.email}: ${e.message}", e)
            return ResponseEntity.badRequest().body(mapOf("error" to "Signup failed"))
        }
    }

    @PostMapping("/login")
    fun login(
        @Valid @RequestBody body: LoginRequest,
    ): ResponseEntity<TokenResponse> {
        logger.info("Login attempt for email: ${body.email}")
        try {
            val auth = am.authenticate(UsernamePasswordAuthenticationToken(body.email, body.password))
            logger.info("Authentication successful for: ${body.email}")
            SecurityContextHolder.getContext().authentication = auth
            val u = userService.byEmail(body.email).orElseThrow()
            val perms = userService.permissionsOf(u)
            val accessToken = jwt.generate(u.email, perms, 3600)
            val refreshToken = jwt.generateRefreshToken(u.email)
            logger.info("Tokens generated successfully for: ${body.email}")
            return ResponseEntity.ok(TokenResponse(accessToken, refreshToken, "Bearer", 3600))
        } catch (e: org.springframework.security.authentication.BadCredentialsException) {
            logger.error("Login failed for ${body.email}: Invalid credentials")
            return ResponseEntity.status(401).build()
        } catch (e: Exception) {
            logger.error("Login failed for ${body.email}: ${e.message}", e)
            throw e
        }
    }

    @PostMapping("/refresh")
    fun refresh(
        @RequestBody body: RefreshTokenRequest,
    ): ResponseEntity<TokenResponse> {
        logger.info("Refresh token request received")
        try {
            // Validate the refresh token
            if (!jwt.isRefreshToken(body.refreshToken)) {
                logger.error("Invalid refresh token provided")
                return ResponseEntity.status(401).build()
            }

            // Check if token is blacklisted
            if (tokenBlacklistService.isTokenBlacklisted(body.refreshToken)) {
                logger.error("Refresh token is blacklisted")
                return ResponseEntity.status(401).build()
            }

            val claims = jwt.parse(body.refreshToken)
            val email = claims.payload.subject

            // Get user and permissions
            val user = userService.byEmail(email).orElseThrow()
            val permissions = userService.permissionsOf(user)

            // Generate new access token
            val newAccessToken = jwt.generateAccessTokenFromRefreshToken(body.refreshToken, permissions)
            val newRefreshToken = jwt.generateRefreshToken(email)

            logger.info("Access token refreshed successfully for: $email")
            return ResponseEntity.ok(TokenResponse(newAccessToken, newRefreshToken, "Bearer", 3600))
        } catch (e: Exception) {
            logger.error("Token refresh failed: ${e.message}", e)
            return ResponseEntity.status(401).build()
        }
    }

    @PostMapping("/logout")
    fun logout(
        @RequestHeader("Authorization") authHeader: String?,
    ): ResponseEntity<Map<String, String>> {
        logger.info("Logout request received")

        if (authHeader?.startsWith("Bearer ") != true) {
            logger.error("No valid authorization header provided")
            return ResponseEntity.badRequest().body(mapOf("error" to "No valid authorization header"))
        }

        try {
            val token = authHeader.substring(7)

            // Blacklist the access token
            tokenBlacklistService.blacklistToken(token, jwt)

            logger.info("User logged out successfully")
            return ResponseEntity.ok(mapOf("message" to "Logged out successfully"))
        } catch (e: Exception) {
            logger.error("Logout failed: ${e.message}", e)
            return ResponseEntity.badRequest().body(mapOf("error" to "Logout failed"))
        }
    }

    @PutMapping("/username")
    fun updateUsername(
        @RequestBody body: UpdateUsernameRequest,
    ): ResponseEntity<Map<String, Any>> {
        val authentication = SecurityContextHolder.getContext().authentication
        logger.info("Username update request for user: ${authentication?.name}")

        try {
            val userEmail = authentication?.name ?: throw IllegalArgumentException("User not authenticated")
            val updatedUser = userService.updateUsername(userEmail, body.username)

            logger.info("Username updated successfully for user: $userEmail")
            return ResponseEntity.ok(
                mapOf(
                    "username" to (updatedUser.username ?: ""),
                ),
            )
        } catch (e: IllegalArgumentException) {
            logger.error("Username update failed for ${authentication?.name}: ${e.message}")
            return ResponseEntity.badRequest().body(mapOf("error" to "Illegal Argument: ${e.message}"))
        } catch (e: Exception) {
            logger.error("Username update failed for ${authentication?.name}: ${e.message}", e)
            return ResponseEntity.badRequest().body(mapOf("error" to "Username update failed"))
        }
    }

    @GetMapping("/me")
    fun getCurrentUser(): ResponseEntity<Map<String, Any>> {
        val authentication = SecurityContextHolder.getContext().authentication
        logger.info("Get current user request for: ${authentication?.name}")

        try {
            val userEmail = authentication?.name ?: throw IllegalArgumentException("User not authenticated")
            val user = userService.byEmail(userEmail).orElseThrow()
            val permissions = userService.permissionsOf(user)

            logger.info("Current user retrieved successfully for: $userEmail")
            return ResponseEntity.ok(
                mapOf(
                    "id" to user.id,
                    "email" to user.email,
                    "username" to (user.username ?: ""),
                    "enabled" to user.enabled,
                    "permissions" to permissions,
                ),
            )
        } catch (e: Exception) {
            logger.error("Failed to get current user: ${e.message}", e)
            return ResponseEntity.status(401).body(mapOf("error" to "Unauthorized"))
        }
    }
}
