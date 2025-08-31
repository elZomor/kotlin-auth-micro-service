package com.auth.infrastructure.persistence

import com.auth.domain.model.UserRole
import com.auth.domain.model.UserRolesGeneralModel
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.jpa.repository.Query
import org.springframework.data.repository.query.Param
import java.util.Optional
import java.util.UUID

interface UserRoleGeneralModelRepo : JpaRepository<UserRolesGeneralModel, UUID> {
    fun findByEmailIgnoreCase(email: String): Optional<List<UserRolesGeneralModel>>
}