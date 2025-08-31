package com.auth.presentation.dto

import java.util.*

/**
 * DTO for assigning a permission to a role
 */
data class AssignPermissionRequest(
    val roleId: UUID,
    val permissionId: UUID
)