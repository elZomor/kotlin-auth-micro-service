package com.auth.infrastructure.persistence

import com.auth.domain.model.Role
import org.springframework.data.jpa.repository.JpaRepository
import java.util.Optional
import java.util.UUID

interface RoleRepo : JpaRepository<Role, UUID> {
    fun findByNameIgnoreCase(name: String): Optional<Role>

    fun existsByNameIgnoreCase(name: String): Boolean
}
