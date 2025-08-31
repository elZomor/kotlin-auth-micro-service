package com.auth.presentation.dto

import jakarta.validation.constraints.NotNull
import java.util.UUID

data class AssignUserRoleRequest(
    @field:NotNull(message = "User ID is required")
    val userId: UUID,
    @field:NotNull(message = "Role ID is required")
    val roleId: UUID,
)
