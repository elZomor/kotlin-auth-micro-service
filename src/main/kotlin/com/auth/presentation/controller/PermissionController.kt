package com.auth.presentation.controller

import com.auth.infrastructure.security.AuthorizationUtils
import com.auth.infrastructure.security.Permissions
import com.auth.domain.service.PermissionService
import com.auth.presentation.dto.CreatePermissionRequest
import org.slf4j.LoggerFactory
import org.springframework.http.ResponseEntity
import org.springframework.security.core.Authentication
import org.springframework.web.bind.annotation.*
import jakarta.validation.Valid
import java.util.UUID

@RestController
@RequestMapping("/admin/permissions")
class PermissionController(
    private val permissionService: PermissionService,
    private val authorizationUtils: AuthorizationUtils
) {
    private val logger = LoggerFactory.getLogger(PermissionController::class.java)

    @PostMapping
    fun createPermission(
        @Valid @RequestBody body: CreatePermissionRequest,
        authentication: Authentication
    ): ResponseEntity<Map<String, Any>> {
        logger.info("Permission creation request by: ${authentication.name}")
        
        // Check authorization
        if (!authorizationUtils.hasPermission(authentication, Permissions.PERMISSION_CREATE)) {
            logger.warn("Unauthorized permission creation attempt by: ${authentication.name}")
            return ResponseEntity.status(403).body(mapOf("error" to "Insufficient permissions. Required: ${Permissions.PERMISSION_CREATE}"))
        }
        
        try {
            val permission = permissionService.createPermission(body.name)
            
            logger.info("Permission created successfully")
            return ResponseEntity.ok(mapOf(
                "message" to "Permission created successfully",
                "permission" to mapOf(
                    "id" to permission.id,
                    "name" to permission.name,
                    "createdAt" to permission.createdAt,
                    "updatedAt" to permission.updatedAt
                )
            ))
        } catch (e: IllegalArgumentException) {
            logger.error("Permission creation failed: ${e.message}")
            return ResponseEntity.badRequest().body(mapOf("error" to "Illegal Exception: ${e.message}"))
        } catch (e: Exception) {
            logger.error("Permission creation failed: ${e.message}", e)
            return ResponseEntity.badRequest().body(mapOf("error" to "Permission creation failed"))
        }
    }

    @GetMapping
    fun getAllPermissions(authentication: Authentication): ResponseEntity<Map<String, Any>> {
        logger.info("Get all permissions request by: ${authentication.name}")
        
        // Check authorization
        if (!authorizationUtils.hasPermission(authentication, Permissions.PERMISSION_READ)) {
            logger.warn("Unauthorized permission read attempt by: ${authentication.name}")
            return ResponseEntity.status(403).body(mapOf("error" to "Insufficient permissions. Required: ${Permissions.PERMISSION_READ}"))
        }
        
        try {
            val permissions = permissionService.getAllPermissions()
            
            return ResponseEntity.ok(mapOf(
                "permissions" to permissions.map { mapOf(
                    "id" to it.id,
                    "name" to it.name,
                    "createdAt" to it.createdAt,
                    "updatedAt" to it.updatedAt
                )}
            ))
        } catch (e: Exception) {
            logger.error("Failed to get permissions: ${e.message}", e)
            return ResponseEntity.badRequest().body(mapOf("error" to "Failed to get permissions"))
        }
    }

    @GetMapping("/{id}")
    fun getPermissionById(
        @PathVariable id: UUID,
        authentication: Authentication
    ): ResponseEntity<Map<String, Any>> {
        logger.info("Get permission by ID request for: $id by: ${authentication.name}")
        
        // Check authorization
        if (!authorizationUtils.hasPermission(authentication, Permissions.PERMISSION_READ)) {
            logger.warn("Unauthorized permission read attempt by: ${authentication.name}")
            return ResponseEntity.status(403).body(mapOf("error" to "Insufficient permissions. Required: ${Permissions.PERMISSION_READ}"))
        }
        
        try {
            val permission = permissionService.getPermissionById(id)
            
            return ResponseEntity.ok(mapOf(
                "permission" to mapOf(
                    "id" to permission.id,
                    "name" to permission.name,
                    "createdAt" to permission.createdAt,
                    "updatedAt" to permission.updatedAt
                )
            ))
        } catch (e: IllegalArgumentException) {
            logger.error("Permission not found: ${e.message}")
            return ResponseEntity.badRequest().body(mapOf("error" to "Illegal Exception: ${e.message}"))
        } catch (e: Exception) {
            logger.error("Failed to get permission: ${e.message}", e)
            return ResponseEntity.badRequest().body(mapOf("error" to "Failed to get permission"))
        }
    }

    @PutMapping("/{id}")
    fun updatePermission(
        @PathVariable id: UUID,
        @Valid @RequestBody body: CreatePermissionRequest,
        authentication: Authentication
    ): ResponseEntity<Map<String, Any>> {
        logger.info("Permission update request for ID: $id by: ${authentication.name}")
        
        // Check authorization
        if (!authorizationUtils.hasPermission(authentication, Permissions.PERMISSION_UPDATE)) {
            logger.warn("Unauthorized permission update attempt by: ${authentication.name}")
            return ResponseEntity.status(403).body(mapOf("error" to "Insufficient permissions. Required: ${Permissions.PERMISSION_UPDATE}"))
        }
        
        try {
            val permission = permissionService.updatePermission(id, body.name)
            
            logger.info("Permission updated successfully")
            return ResponseEntity.ok(mapOf(
                "message" to "Permission updated successfully",
                "permission" to mapOf(
                    "id" to permission.id,
                    "name" to permission.name,
                    "createdAt" to permission.createdAt,
                    "updatedAt" to permission.updatedAt
                )
            ))
        } catch (e: IllegalArgumentException) {
            logger.error("Permission update failed: ${e.message}")
            return ResponseEntity.badRequest().body(mapOf("error" to "Illegal Exception: ${e.message}"))
        } catch (e: Exception) {
            logger.error("Permission update failed: ${e.message}", e)
            return ResponseEntity.badRequest().body(mapOf("error" to "Permission update failed"))
        }
    }

    @DeleteMapping("/{id}")
    fun deletePermission(
        @PathVariable id: UUID,
        authentication: Authentication
    ): ResponseEntity<Map<String, String>> {
        logger.info("Permission deletion request for ID: $id by: ${authentication.name}")
        
        // Check authorization
        if (!authorizationUtils.hasPermission(authentication, Permissions.PERMISSION_DELETE)) {
            logger.warn("Unauthorized permission deletion attempt by: ${authentication.name}")
            return ResponseEntity.status(403).body(mapOf("error" to "Insufficient permissions. Required: ${Permissions.PERMISSION_DELETE}"))
        }
        
        try {
            permissionService.deletePermission(id)
            
            logger.info("Permission deleted successfully")
            return ResponseEntity.ok(mapOf("message" to "Permission deleted successfully"))
        } catch (e: IllegalArgumentException) {
            logger.error("Permission deletion failed: ${e.message}")
            return ResponseEntity.badRequest().body(mapOf("error" to "Illegal Exception: ${e.message}"))
        } catch (e: Exception) {
            logger.error("Permission deletion failed: ${e.message}", e)
            return ResponseEntity.badRequest().body(mapOf("error" to "Permission deletion failed"))
        }
    }
}