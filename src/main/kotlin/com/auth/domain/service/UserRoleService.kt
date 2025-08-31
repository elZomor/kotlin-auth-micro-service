package com.auth.domain.service

import com.auth.domain.model.UserRole
import com.auth.infrastructure.persistence.RoleRepo
import com.auth.infrastructure.persistence.UserRepo
import com.auth.infrastructure.persistence.UserRoleRepo
import jakarta.transaction.Transactional
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Service
import java.util.UUID

@Service
class UserRoleService(
    private val userRepo: UserRepo,
    private val roleRepo: RoleRepo,
    private val userRoleRepo: UserRoleRepo,
) {
    private val logger = LoggerFactory.getLogger(UserRoleService::class.java)

    @Transactional
    fun assignUserToRole(
        userId: UUID,
        roleId: UUID,
    ): UserRole {
        logger.info("Assigning user $userId to role $roleId")

        // Check if user exists
        val user =
            userRepo.findById(userId)
                .orElseThrow { IllegalArgumentException("User not found with ID: $userId") }

        // Check if role exists
        val role =
            roleRepo.findById(roleId)
                .orElseThrow { IllegalArgumentException("Role not found with ID: $roleId") }

        // Check if assignment already exists
        if (userRoleRepo.existsByUserIdAndRoleId(userId, roleId)) {
            throw IllegalArgumentException("User $userId is already assigned to role $roleId")
        }

        val userRole = UserRole(userId = userId, roleId = roleId)
        val savedUserRole = userRoleRepo.save(userRole)

        logger.info("Successfully assigned user ${user.email} to role ${role.name}")
        return savedUserRole
    }

    @Transactional
    fun removeUserFromRole(
        userId: UUID,
        roleId: UUID,
    ) {
        logger.info("Removing user $userId from role $roleId")

        if (!userRoleRepo.existsByUserIdAndRoleId(userId, roleId)) {
            throw IllegalArgumentException("User $userId is not assigned to role $roleId")
        }

        userRoleRepo.deleteByUserIdAndRoleId(userId, roleId)
        logger.info("Successfully removed user $userId from role $roleId")
    }

    fun getUserRoles(userId: UUID): List<UserRole> {
        return userRoleRepo.findByUserId(userId)
    }

    fun getRoleUsers(roleId: UUID): List<UserRole> {
        return userRoleRepo.findByRoleId(roleId)
    }
}
