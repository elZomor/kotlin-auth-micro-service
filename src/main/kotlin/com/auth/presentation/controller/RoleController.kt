package com.auth.presentation.controller

import com.auth.infrastructure.security.AuthorizationUtils
import com.auth.infrastructure.security.Permissions
import com.auth.domain.service.RoleService
import com.auth.presentation.dto.CreateRoleRequest
import org.slf4j.LoggerFactory
import org.springframework.http.ResponseEntity
import org.springframework.security.core.Authentication
import org.springframework.web.bind.annotation.*
import jakarta.validation.Valid
import java.util.UUID

@RestController
@RequestMapping("/admin/roles")
class RoleController(
    private val roleService: RoleService,
    private val authorizationUtils: AuthorizationUtils
) {
    private val logger = LoggerFactory.getLogger(RoleController::class.java)

    @PostMapping
    fun createRole(
        @Valid @RequestBody body: CreateRoleRequest,
        authentication: Authentication
    ): ResponseEntity<Map<String, Any>> {
        logger.info("Role creation request by: ${authentication.name}")
        
        // Check authorization
        if (!authorizationUtils.hasPermission(authentication, Permissions.ROLE_CREATE)) {
            logger.warn("Unauthorized role creation attempt by: ${authentication.name}")
            return ResponseEntity.status(403).body(mapOf("error" to "Insufficient permissions. Required: ${Permissions.ROLE_CREATE}"))
        }
        
        try {
            val role = roleService.createRole(body.name)
            
            logger.info("Role created successfully")
            return ResponseEntity.ok(mapOf(
                "message" to "Role created successfully",
                "role" to mapOf(
                    "id" to role.id,
                    "name" to role.name,
                    "createdAt" to role.createdAt,
                    "updatedAt" to role.updatedAt
                )
            ))
        } catch (e: IllegalArgumentException) {
            logger.error("Role creation failed: ${e.message}")
            return ResponseEntity.badRequest().body(mapOf("error" to "Illegal exception: ${e.message}"))
        } catch (e: Exception) {
            logger.error("Role creation failed: ${e.message}", e)
            return ResponseEntity.badRequest().body(mapOf("error" to "Role creation failed"))
        }
    }

    @GetMapping
    fun getAllRoles(authentication: Authentication): ResponseEntity<Map<String, Any>> {
        logger.info("Get all roles request by: ${authentication.name}")
        
        // Check authorization
        if (!authorizationUtils.hasPermission(authentication, Permissions.ROLE_READ)) {
            logger.warn("Unauthorized role read attempt by: ${authentication.name}")
            return ResponseEntity.status(403).body(mapOf("error" to "Insufficient permissions. Required: ${Permissions.ROLE_READ}"))
        }
        
        try {
            val roles = roleService.getAllRoles()
            
            return ResponseEntity.ok(mapOf(
                "roles" to roles.map { mapOf(
                    "id" to it.id,
                    "name" to it.name,
                    "createdAt" to it.createdAt,
                    "updatedAt" to it.updatedAt
                )}
            ))
        } catch (e: Exception) {
            logger.error("Failed to get roles: ${e.message}", e)
            return ResponseEntity.badRequest().body(mapOf("error" to "Failed to get roles"))
        }
    }

    @GetMapping("/{id}")
    fun getRoleById(
        @PathVariable id: UUID,
        authentication: Authentication
    ): ResponseEntity<Map<String, Any>> {
        logger.info("Get role by ID request for: $id by: ${authentication.name}")
        
        // Check authorization
        if (!authorizationUtils.hasPermission(authentication, Permissions.ROLE_READ)) {
            logger.warn("Unauthorized role read attempt by: ${authentication.name}")
            return ResponseEntity.status(403).body(mapOf("error" to "Insufficient permissions. Required: ${Permissions.ROLE_READ}"))
        }
        
        try {
            val role = roleService.getRoleById(id)
            
            return ResponseEntity.ok(mapOf(
                "role" to mapOf(
                    "id" to role.id,
                    "name" to role.name,
                    "createdAt" to role.createdAt,
                    "updatedAt" to role.updatedAt
                )
            ))
        } catch (e: IllegalArgumentException) {
            logger.error("Role not found: ${e.message}")
            return ResponseEntity.badRequest().body(mapOf("error" to "Illegal exception: ${e.message}"))
        } catch (e: Exception) {
            logger.error("Failed to get role: ${e.message}", e)
            return ResponseEntity.badRequest().body(mapOf("error" to "Failed to get role"))
        }
    }

    @PutMapping("/{id}")
    fun updateRole(
        @PathVariable id: UUID,
        @Valid @RequestBody body: CreateRoleRequest,
        authentication: Authentication
    ): ResponseEntity<Map<String, Any>> {
        logger.info("Role update request for ID: $id by: ${authentication.name}")
        
        // Check authorization
        if (!authorizationUtils.hasPermission(authentication, Permissions.ROLE_UPDATE)) {
            logger.warn("Unauthorized role update attempt by: ${authentication.name}")
            return ResponseEntity.status(403).body(mapOf("error" to "Insufficient permissions. Required: ${Permissions.ROLE_UPDATE}"))
        }
        
        try {
            val role = roleService.updateRole(id, body.name)
            
            logger.info("Role updated successfully")
            return ResponseEntity.ok(mapOf(
                "message" to "Role updated successfully",
                "role" to mapOf(
                    "id" to role.id,
                    "name" to role.name,
                    "createdAt" to role.createdAt,
                    "updatedAt" to role.updatedAt
                )
            ))
        } catch (e: IllegalArgumentException) {
            logger.error("Role update failed: ${e.message}")
            return ResponseEntity.badRequest().body(mapOf("error" to "Illegal exception: ${e.message}"))
        } catch (e: Exception) {
            logger.error("Role update failed: ${e.message}", e)
            return ResponseEntity.badRequest().body(mapOf("error" to "Role update failed"))
        }
    }

    @DeleteMapping("/{id}")
    fun deleteRole(
        @PathVariable id: UUID,
        authentication: Authentication
    ): ResponseEntity<Map<String, String>> {
        logger.info("Role deletion request for ID: $id by: ${authentication.name}")
        
        // Check authorization
        if (!authorizationUtils.hasPermission(authentication, Permissions.ROLE_DELETE)) {
            logger.warn("Unauthorized role deletion attempt by: ${authentication.name}")
            return ResponseEntity.status(403).body(mapOf("error" to "Insufficient permissions. Required: ${Permissions.ROLE_DELETE}"))
        }
        
        try {
            roleService.deleteRole(id)
            
            logger.info("Role deleted successfully")
            return ResponseEntity.ok(mapOf("message" to "Role deleted successfully"))
        } catch (e: IllegalArgumentException) {
            logger.error("Role deletion failed: ${e.message}")
            return ResponseEntity.badRequest().body(mapOf("error" to "Illegal exception: ${e.message}"))
        } catch (e: Exception) {
            logger.error("Role deletion failed: ${e.message}", e)
            return ResponseEntity.badRequest().body(mapOf("error" to "Role deletion failed"))
        }
    }
}