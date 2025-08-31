package com.auth.presentation.dto

import java.time.OffsetDateTime
import java.util.*

/**
 * DTO for user responses (without password)
 */
data class UserResponse(
    val id: UUID,
    val email: String,
    val username: String?,
    val enabled: Boolean,
    val createdAt: OffsetDateTime?,
    val updatedAt: OffsetDateTime?,
    val roles: List<String> = emptyList()
)