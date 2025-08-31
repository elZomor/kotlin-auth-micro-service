package com.auth.infrastructure.persistence

import com.auth.domain.model.Permission
import org.springframework.data.jpa.repository.JpaRepository
import java.util.UUID
import java.util.Optional

interface PermissionRepo : JpaRepository<Permission, UUID> {
    fun findByNameIgnoreCase(name: String): Optional<Permission>
    fun existsByNameIgnoreCase(name: String): Boolean
}