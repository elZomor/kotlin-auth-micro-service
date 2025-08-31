package com.auth.presentation.dto

import jakarta.validation.constraints.NotBlank
import jakarta.validation.constraints.Size

data class CreateRoleRequest(
    @field:NotBlank(message = "Role name is required")
    @field:Size(min = 2, max = 50, message = "Role name must be between 2 and 50 characters")
    val name: String
)