package com.auth.domain.model

import jakarta.persistence.Entity
import jakarta.persistence.Id
import jakarta.persistence.Table
import java.util.UUID

@Entity
@Table(name = "role_permissions")
data class RolePermission(
    @Id
    val id: UUID = UUID.randomUUID(),
    val roleId: UUID,
    val permissionId: UUID,
)
