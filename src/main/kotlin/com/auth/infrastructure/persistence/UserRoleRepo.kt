package com.auth.infrastructure.persistence

import com.auth.domain.model.UserRole
import org.springframework.data.jpa.repository.JpaRepository
import java.util.UUID

interface UserRoleRepo : JpaRepository<UserRole, UserRole> {
    fun findByUserId(userId: UUID): List<UserRole>

    fun findByRoleId(roleId: UUID): List<UserRole>

    fun existsByUserIdAndRoleId(
        userId: UUID,
        roleId: UUID,
    ): Boolean

    fun deleteByUserIdAndRoleId(
        userId: UUID,
        roleId: UUID,
    )
}
