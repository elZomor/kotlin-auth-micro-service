package com.auth.common

import com.auth.domain.model.Permission
import com.auth.domain.model.Role
import com.auth.domain.model.RolePermission
import com.auth.infrastructure.persistence.PermissionRepo
import com.auth.infrastructure.persistence.RolePermissionRepo
import com.auth.infrastructure.persistence.RoleRepo
import jakarta.annotation.PostConstruct
import org.springframework.context.annotation.Profile
import org.springframework.stereotype.Component
import java.time.OffsetDateTime
import java.util.UUID

@Component
class TestDataInitializer(
    private val roleRepo: RoleRepo,
    private val permissionRepo: PermissionRepo,
    private val rolePermissionRepo: RolePermissionRepo,
) {
    @PostConstruct
    fun initializeTestData() {
        // Create permissions
        val userReadPermission = Permission(
            id = UUID.randomUUID(),
            name = "user.read",
            createdAt = OffsetDateTime.now(),
            updatedAt = OffsetDateTime.now(),
        )
        val userWritePermission = Permission(
            id = UUID.randomUUID(),
            name = "user.write",
            createdAt = OffsetDateTime.now(),
            updatedAt = OffsetDateTime.now(),
        )
        val roleReadPermission = Permission(
            id = UUID.randomUUID(),
            name = "role.read",
            createdAt = OffsetDateTime.now(),
            updatedAt = OffsetDateTime.now(),
        )
        val roleWritePermission = Permission(
            id = UUID.randomUUID(),
            name = "role.write",
            createdAt = OffsetDateTime.now(),
            updatedAt = OffsetDateTime.now(),
        )

        permissionRepo.saveAll(listOf(userReadPermission, userWritePermission, roleReadPermission, roleWritePermission))

        // Create roles
        val adminRole = Role(
            id = UUID.randomUUID(),
            name = "ROLE_ADMIN",
            createdAt = OffsetDateTime.now(),
            updatedAt = OffsetDateTime.now(),
        )
        val userRole = Role(
            id = UUID.randomUUID(),
            name = "USER",
            createdAt = OffsetDateTime.now(),
            updatedAt = OffsetDateTime.now(),
        )

        val savedRoles = roleRepo.saveAll(listOf(adminRole, userRole))
        val savedAdminRole = savedRoles.find { it.name == "ROLE_ADMIN" }!!
        val savedUserRole = savedRoles.find { it.name == "USER" }!!

        // Create role-permission mappings
        val adminRolePermissions = listOf(
            RolePermission(
                id = UUID.randomUUID(),
                roleId = savedAdminRole.id,
                permissionId = userReadPermission.id,
            ),
            RolePermission(
                id = UUID.randomUUID(),
                roleId = savedAdminRole.id,
                permissionId = userWritePermission.id,
            ),
            RolePermission(
                id = UUID.randomUUID(),
                roleId = savedAdminRole.id,
                permissionId = roleReadPermission.id,
            ),
            RolePermission(
                id = UUID.randomUUID(),
                roleId = savedAdminRole.id,
                permissionId = roleWritePermission.id,
            ),
        )

        val userRolePermissions = listOf(
            RolePermission(
                id = UUID.randomUUID(),
                roleId = savedUserRole.id,
                permissionId = userReadPermission.id,
            ),
        )

        rolePermissionRepo.saveAll(adminRolePermissions + userRolePermissions)
    }
}