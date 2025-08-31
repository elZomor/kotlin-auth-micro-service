package com.auth.domain.service

import com.auth.domain.model.Permission
import com.auth.infrastructure.persistence.PermissionRepo
import jakarta.transaction.Transactional
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Service
import java.time.OffsetDateTime
import java.util.UUID

@Service
class PermissionService(
    private val permissionRepo: PermissionRepo
) {
    private val logger = LoggerFactory.getLogger(PermissionService::class.java)

    @Transactional
    fun createPermission(name: String): Permission {
        logger.info("Creating permission: $name")
        
        // Check if permission already exists
        if (permissionRepo.existsByNameIgnoreCase(name)) {
            throw IllegalArgumentException("Permission with name '$name' already exists")
        }
        
        val permission = Permission(
            name = name,
            createdAt = OffsetDateTime.now(),
            updatedAt = OffsetDateTime.now()
        )
        
        val savedPermission = permissionRepo.save(permission)
        logger.info("Permission created successfully: ${savedPermission.name} with ID: ${savedPermission.id}")
        return savedPermission
    }

    fun getAllPermissions(): List<Permission> {
        return permissionRepo.findAll()
    }

    fun getPermissionById(id: UUID): Permission {
        return permissionRepo.findById(id)
            .orElseThrow { IllegalArgumentException("Permission not found with ID: $id") }
    }

    fun getPermissionByName(name: String): Permission {
        return permissionRepo.findByNameIgnoreCase(name)
            .orElseThrow { IllegalArgumentException("Permission not found with name: $name") }
    }

    @Transactional
    fun updatePermission(id: UUID, newName: String): Permission {
        logger.info("Updating permission with ID: $id to name: $newName")
        
        val permission = permissionRepo.findById(id)
            .orElseThrow { IllegalArgumentException("Permission not found with ID: $id") }
        
        // Check if new name already exists (excluding current permission)
        if (permissionRepo.existsByNameIgnoreCase(newName) && permission.name != newName) {
            throw IllegalArgumentException("Permission with name '$newName' already exists")
        }
        
        val updatedPermission = permission.copy(
            name = newName,
            updatedAt = OffsetDateTime.now()
        )
        
        val savedPermission = permissionRepo.save(updatedPermission)
        logger.info("Permission updated successfully: ${savedPermission.name}")
        return savedPermission
    }

    @Transactional
    fun deletePermission(id: UUID) {
        logger.info("Deleting permission with ID: $id")
        
        if (!permissionRepo.existsById(id)) {
            throw IllegalArgumentException("Permission not found with ID: $id")
        }
        
        permissionRepo.deleteById(id)
        logger.info("Permission deleted successfully with ID: $id")
    }
}