package com.auth.presentation.controller

import com.auth.domain.service.UserRoleService
import com.auth.infrastructure.security.AuthorizationUtils
import com.auth.infrastructure.security.Permissions
import com.auth.presentation.dto.AssignUserRoleRequest
import jakarta.validation.Valid
import org.slf4j.LoggerFactory
import org.springframework.http.ResponseEntity
import org.springframework.security.core.Authentication
import org.springframework.web.bind.annotation.DeleteMapping
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import java.util.UUID

@RestController
@RequestMapping("/admin/user-roles")
class UserRoleController(
    private val userRoleService: UserRoleService,
    private val authorizationUtils: AuthorizationUtils,
) {
    private val logger = LoggerFactory.getLogger(UserRoleController::class.java)

    @PostMapping("/assign")
    fun assignUserToRole(
        @Valid @RequestBody body: AssignUserRoleRequest,
        authentication: Authentication,
    ): ResponseEntity<Map<String, Any>> {
        logger.info("User role assignment request by: ${authentication.name}")

        // Check authorization
        if (!authorizationUtils.hasPermission(authentication, Permissions.USER_ROLE_ASSIGN)) {
            logger.warn("Unauthorized user role assignment attempt by: ${authentication.name}")
            return ResponseEntity.status(403).body(mapOf("error" to "Insufficient permissions. Required: ${Permissions.USER_ROLE_ASSIGN}"))
        }

        try {
            val userRole = userRoleService.assignUserToRole(body.userId, body.roleId)

            logger.info("User role assigned successfully")
            return ResponseEntity.ok(
                mapOf(
                    "message" to "User assigned to role successfully",
                    "userRole" to
                        mapOf(
                            "id" to userRole.id,
                            "userId" to userRole.userId,
                            "roleId" to userRole.roleId,
                        ),
                ),
            )
        } catch (e: IllegalArgumentException) {
            logger.error("User role assignment failed: ${e.message}")
            return ResponseEntity.badRequest().body(mapOf("error" to "Illegal ${e.message}"))
        } catch (e: Exception) {
            logger.error("User role assignment failed: ${e.message}", e)
            return ResponseEntity.badRequest().body(mapOf("error" to "User role assignment failed"))
        }
    }

    @DeleteMapping("/remove")
    fun removeUserFromRole(
        @RequestParam userId: UUID,
        @RequestParam roleId: UUID,
        authentication: Authentication,
    ): ResponseEntity<Map<String, String>> {
        logger.info("User role removal request by: ${authentication.name}")

        // Check authorization
        if (!authorizationUtils.hasPermission(authentication, Permissions.USER_ROLE_REMOVE)) {
            logger.warn("Unauthorized user role removal attempt by: ${authentication.name}")
            return ResponseEntity.status(403).body(mapOf("error" to "Insufficient permissions. Required: ${Permissions.USER_ROLE_REMOVE}"))
        }

        try {
            userRoleService.removeUserFromRole(userId, roleId)

            logger.info("User role removed successfully")
            return ResponseEntity.ok(mapOf("message" to "User removed from role successfully"))
        } catch (e: IllegalArgumentException) {
            logger.error("User role removal failed: ${e.message}")
            return ResponseEntity.badRequest().body(mapOf("error" to "Illegal ${e.message}"))
        } catch (e: Exception) {
            logger.error("User role removal failed: ${e.message}", e)
            return ResponseEntity.badRequest().body(mapOf("error" to "User role removal failed"))
        }
    }

    @GetMapping("/user/{userId}")
    fun getUserRoles(
        @PathVariable userId: UUID,
        authentication: Authentication,
    ): ResponseEntity<Map<String, Any>> {
        logger.info("Get user roles request for user: $userId by: ${authentication.name}")

        // Check authorization
        if (!authorizationUtils.hasPermission(authentication, Permissions.USER_ROLE_READ)) {
            logger.warn("Unauthorized user role read attempt by: ${authentication.name}")
            return ResponseEntity.status(403).body(mapOf("error" to "Insufficient permissions. Required: ${Permissions.USER_ROLE_READ}"))
        }

        try {
            val userRoles = userRoleService.getUserRoles(userId)

            return ResponseEntity.ok(
                mapOf(
                    "userId" to userId,
                    "roles" to
                        userRoles.map {
                            mapOf(
                                "id" to it.id,
                                "roleId" to it.roleId,
                            )
                        },
                ),
            )
        } catch (e: Exception) {
            logger.error("Failed to get user roles: ${e.message}", e)
            return ResponseEntity.badRequest().body(mapOf("error" to "Failed to get user roles"))
        }
    }

    @GetMapping("/role/{roleId}")
    fun getRoleUsers(
        @PathVariable roleId: UUID,
        authentication: Authentication,
    ): ResponseEntity<Map<String, Any>> {
        logger.info("Get role users request for role: $roleId by: ${authentication.name}")

        // Check authorization
        if (!authorizationUtils.hasPermission(authentication, Permissions.USER_ROLE_READ)) {
            logger.warn("Unauthorized user role read attempt by: ${authentication.name}")
            return ResponseEntity.status(403).body(mapOf("error" to "Insufficient permissions. Required: ${Permissions.USER_ROLE_READ}"))
        }

        try {
            val roleUsers = userRoleService.getRoleUsers(roleId)

            return ResponseEntity.ok(
                mapOf(
                    "roleId" to roleId,
                    "users" to
                        roleUsers.map {
                            mapOf(
                                "id" to it.id,
                                "userId" to it.userId,
                            )
                        },
                ),
            )
        } catch (e: Exception) {
            logger.error("Failed to get role users: ${e.message}", e)
            return ResponseEntity.badRequest().body(mapOf("error" to "Failed to get role users"))
        }
    }
}
