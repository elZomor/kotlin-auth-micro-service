package com.auth.domain.model

import jakarta.persistence.Entity
import jakarta.persistence.Id
import jakarta.persistence.Table
import java.util.UUID

@Entity
@Table(name = "user_roles_permissions_generalmodel")
data class UserRolesPermissionsGeneralModel(
    @Id
    val id: UUID,
    val email: String,
    val username: String?,
    val roleName: String,
    val enabled: Boolean,
    val permissionName: String,
)
