package com.auth.domain.service

import com.auth.domain.model.Role
import com.auth.infrastructure.persistence.RoleRepo
import jakarta.transaction.Transactional
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Service
import java.time.OffsetDateTime
import java.util.UUID

@Service
class RoleService(
    private val roleRepo: RoleRepo,
) {
    private val logger = LoggerFactory.getLogger(RoleService::class.java)

    @Transactional
    fun createRole(name: String): Role {
        logger.info("Creating role: $name")

        // Check if role already exists
        if (roleRepo.existsByNameIgnoreCase(name)) {
            throw IllegalArgumentException("Role with name '$name' already exists")
        }

        val role =
            Role(
                name = name,
                createdAt = OffsetDateTime.now(),
                updatedAt = OffsetDateTime.now(),
            )

        val savedRole = roleRepo.save(role)
        logger.info("Role created successfully: ${savedRole.name} with ID: ${savedRole.id}")
        return savedRole
    }

    fun getAllRoles(): List<Role> {
        return roleRepo.findAll()
    }

    fun getRoleById(id: UUID): Role {
        return roleRepo.findById(id)
            .orElseThrow { IllegalArgumentException("Role not found with ID: $id") }
    }

    fun getRoleByName(name: String): Role {
        return roleRepo.findByNameIgnoreCase(name)
            .orElseThrow { IllegalArgumentException("Role not found with name: $name") }
    }

    @Transactional
    fun updateRole(
        id: UUID,
        newName: String,
    ): Role {
        logger.info("Updating role with ID: $id to name: $newName")

        val role =
            roleRepo.findById(id)
                .orElseThrow { IllegalArgumentException("Role not found with ID: $id") }

        // Check if new name already exists (excluding current role)
        if (roleRepo.existsByNameIgnoreCase(newName) && role.name != newName) {
            throw IllegalArgumentException("Role with name '$newName' already exists")
        }

        val updatedRole =
            role.copy(
                name = newName,
                updatedAt = OffsetDateTime.now(),
            )

        val savedRole = roleRepo.save(updatedRole)
        logger.info("Role updated successfully: ${savedRole.name}")
        return savedRole
    }

    @Transactional
    fun deleteRole(id: UUID) {
        logger.info("Deleting role with ID: $id")

        if (!roleRepo.existsById(id)) {
            throw IllegalArgumentException("Role not found with ID: $id")
        }

        roleRepo.deleteById(id)
        logger.info("Role deleted successfully with ID: $id")
    }
}
