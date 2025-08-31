package com.auth.presentation.dto

import jakarta.validation.constraints.NotBlank
import jakarta.validation.constraints.Size

data class CreatePermissionRequest(
    @field:NotBlank(message = "Permission name is required")
    @field:Size(min = 2, max = 100, message = "Permission name must be between 2 and 100 characters")
    val name: String
)