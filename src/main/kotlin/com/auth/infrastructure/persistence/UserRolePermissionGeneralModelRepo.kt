package com.auth.infrastructure.persistence

import com.auth.domain.model.UserRolesPermissionsGeneralModel
import org.springframework.data.jpa.repository.JpaRepository
import java.util.UUID

interface UserRolePermissionGeneralModelRepo : JpaRepository<UserRolesPermissionsGeneralModel, UUID> {
    fun findByEmailIgnoreCase(email: String): List<UserRolesPermissionsGeneralModel>
}
