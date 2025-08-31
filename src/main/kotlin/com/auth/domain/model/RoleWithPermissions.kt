package com.auth.domain.model

import java.time.OffsetDateTime
import java.util.UUID

/**
 * Enhanced role model that includes associated permissions
 * Useful for queries that need to load role with its permissions
 */
data class RoleWithPermissions(
    val id: UUID,
    val name: String,
    val createdAt: OffsetDateTime?,
    val updatedAt: OffsetDateTime?,
    val permissions: List<Permission> = emptyList(),
)
