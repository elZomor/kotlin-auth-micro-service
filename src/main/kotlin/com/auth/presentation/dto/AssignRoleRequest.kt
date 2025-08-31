package com.auth.presentation.dto

import java.util.UUID

/**
 * DTO for assigning a role to a user
 */
data class AssignRoleRequest(
    val userId: UUID,
    val roleId: UUID,
)
