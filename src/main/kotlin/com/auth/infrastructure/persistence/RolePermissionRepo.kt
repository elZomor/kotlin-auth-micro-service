package com.auth.infrastructure.persistence

import com.auth.domain.model.RolePermission
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.jpa.repository.Query
import org.springframework.data.repository.query.Param
import java.util.UUID

interface RolePermissionRepo : JpaRepository<RolePermission, RolePermission> {
    fun findByRoleId(roleId: UUID): List<RolePermission>
    fun findByPermissionId(permissionId: UUID): List<RolePermission>
    fun existsByRoleIdAndPermissionId(roleId: UUID, permissionId: UUID): Boolean
    fun deleteByRoleIdAndPermissionId(roleId: UUID, permissionId: UUID)
}