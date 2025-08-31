package com.auth.presentation.dto

/**
 * DTO for creating a new user
 */
data class CreateUserRequest(
    val email: String,
    val username: String? = null,
    val password: String,
)
