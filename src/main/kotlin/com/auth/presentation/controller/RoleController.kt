package com.auth.presentation.controller

import com.auth.domain.service.RoleService
import com.auth.infrastructure.security.AuthorizationUtils
import com.auth.presentation.dto.CreateRoleRequest
import jakarta.validation.Valid
import org.slf4j.LoggerFactory
import org.springframework.http.ResponseEntity
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.web.bind.annotation.DeleteMapping
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.PutMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import java.util.UUID

@RestController
@RequestMapping("/roles")
class RoleController(
    private val roleService: RoleService,
    private val authorizationUtils: AuthorizationUtils,
) {
    private val logger = LoggerFactory.getLogger(RoleController::class.java)

    @PostMapping
    fun createRole(
        @Valid @RequestBody body: CreateRoleRequest,
    ): ResponseEntity<Map<String, Any>> {
        val authentication = SecurityContextHolder.getContext().authentication
        logger.info("Role creation request by: ${authentication.name}")

        // Check authorization
        if (!authorizationUtils.hasPermission(authentication, "ADMIN")) {
            logger.warn("Unauthorized role creation attempt by: ${authentication.name}")
            return ResponseEntity.status(403).body(mapOf("error" to "Insufficient permissions. Required: ADMIN"))
        }

        try {
            val role = roleService.createRole(body.name)

            logger.info("Role created successfully")
            return ResponseEntity.ok(
                mapOf(
                    "id" to role.id,
                    "name" to role.name,
                ),
            )
        } catch (e: IllegalArgumentException) {
            logger.error("Role creation failed: ${e.message}")
            return ResponseEntity.badRequest().body(mapOf("error" to (e.message ?: "Unknown error")))
        } catch (e: Exception) {
            logger.error("Role creation failed: ${e.message}", e)
            return ResponseEntity.badRequest().body(mapOf("error" to "Role creation failed"))
        }
    }

    @GetMapping
    fun getAllRoles(): ResponseEntity<Any> {
        val authentication = SecurityContextHolder.getContext().authentication
        logger.info("Get all roles request by: ${authentication.name}")

        // Check authorization
        if (!authorizationUtils.hasPermission(authentication, "ADMIN")) {
            logger.warn("Unauthorized role read attempt by: ${authentication.name}")
            return ResponseEntity.status(403).body(mapOf("error" to "Insufficient permissions. Required: ADMIN"))
        }

        try {
            val roles = roleService.getAllRoles()

            return ResponseEntity.ok(
                roles.map {
                    mapOf(
                        "id" to it.id,
                        "name" to it.name,
                    )
                },
            )
        } catch (e: Exception) {
            logger.error("Failed to get roles: ${e.message}", e)
            return ResponseEntity.badRequest().body(mapOf("error" to "Failed to get roles"))
        }
    }

    @GetMapping("/{id}")
    fun getRoleById(
        @PathVariable id: UUID,
    ): ResponseEntity<Map<String, Any>> {
        val authentication = SecurityContextHolder.getContext().authentication
        logger.info("Get role by ID request for: $id by: ${authentication.name}")

        // Check authorization
        if (!authorizationUtils.hasPermission(authentication, "ADMIN")) {
            logger.warn("Unauthorized role read attempt by: ${authentication.name}")
            return ResponseEntity.status(403).body(mapOf("error" to "Insufficient permissions. Required: ADMIN"))
        }

        try {
            val role = roleService.getRoleById(id)

            return ResponseEntity.ok(
                mapOf(
                    "id" to role.id,
                    "name" to role.name,
                ),
            )
        } catch (e: IllegalArgumentException) {
            logger.error("Role not found: ${e.message}")
            return ResponseEntity.notFound().build()
        } catch (e: Exception) {
            logger.error("Failed to get role: ${e.message}", e)
            return ResponseEntity.badRequest().body(mapOf("error" to "Failed to get role"))
        }
    }

    @PutMapping("/{id}")
    fun updateRole(
        @PathVariable id: UUID,
        @Valid @RequestBody body: CreateRoleRequest,
    ): ResponseEntity<Map<String, Any>> {
        val authentication = SecurityContextHolder.getContext().authentication
        logger.info("Role update request for ID: $id by: ${authentication.name}")

        // Check authorization
        if (!authorizationUtils.hasPermission(authentication, "ADMIN")) {
            logger.warn("Unauthorized role update attempt by: ${authentication.name}")
            return ResponseEntity.status(403).body(mapOf("error" to "Insufficient permissions. Required: ADMIN"))
        }

        try {
            val role = roleService.updateRole(id, body.name)

            logger.info("Role updated successfully")
            return ResponseEntity.ok(
                mapOf(
                    "id" to role.id,
                    "name" to role.name,
                ),
            )
        } catch (e: IllegalArgumentException) {
            logger.error("Role update failed: ${e.message}")
            return when {
                e.message?.contains("not found", ignoreCase = true) == true -> ResponseEntity.notFound().build()
                else -> ResponseEntity.badRequest().body(mapOf("error" to (e.message ?: "Unknown error")))
            }
        } catch (e: Exception) {
            logger.error("Role update failed: ${e.message}", e)
            return ResponseEntity.badRequest().body(mapOf("error" to "Role update failed"))
        }
    }

    @DeleteMapping("/{id}")
    fun deleteRole(
        @PathVariable id: UUID,
    ): ResponseEntity<Map<String, String>> {
        val authentication = SecurityContextHolder.getContext().authentication
        logger.info("Role deletion request for ID: $id by: ${authentication.name}")

        // Check authorization
        if (!authorizationUtils.hasPermission(authentication, "ADMIN")) {
            logger.warn("Unauthorized role deletion attempt by: ${authentication.name}")
            return ResponseEntity.status(403).body(mapOf("error" to "Insufficient permissions. Required: ADMIN"))
        }

        try {
            roleService.deleteRole(id)

            logger.info("Role deleted successfully")
            return ResponseEntity.ok(mapOf("message" to "Role deleted successfully"))
        } catch (e: IllegalArgumentException) {
            logger.error("Role deletion failed: ${e.message}")
            return ResponseEntity.notFound().build()
        } catch (e: Exception) {
            logger.error("Role deletion failed: ${e.message}", e)
            return ResponseEntity.badRequest().body(mapOf("error" to "Role deletion failed"))
        }
    }
}
