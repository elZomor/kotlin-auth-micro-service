package com.auth.infrastructure.persistence

import com.auth.domain.model.UserRole
import com.auth.domain.model.UserRolesGeneralModel
import com.auth.domain.model.UserRolesPermissionsGeneralModel
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.jpa.repository.Query
import org.springframework.data.repository.query.Param
import java.util.Optional
import java.util.UUID

interface UserRolePermissionGeneralModelRepo : JpaRepository<UserRolesPermissionsGeneralModel, UUID> {
    fun findByEmailIgnoreCase(email: String): List<UserRolesPermissionsGeneralModel>
}