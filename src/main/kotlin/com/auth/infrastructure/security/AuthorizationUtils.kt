package com.auth.infrastructure.security

import org.springframework.security.core.Authentication
import org.springframework.stereotype.Component

@Component
class AuthorizationUtils {
    fun hasPermission(
        authentication: Authentication,
        permission: String,
    ): Boolean {
        return authentication.authorities.any { it.authority == permission }
    }

    fun hasAnyPermission(
        authentication: Authentication,
        permissions: List<String>,
    ): Boolean {
        return authentication.authorities.any { authority ->
            permissions.any { permission -> authority.authority == permission }
        }
    }

    fun hasAllPermissions(
        authentication: Authentication,
        permissions: List<String>,
    ): Boolean {
        return permissions.all { permission ->
            authentication.authorities.any { it.authority == permission }
        }
    }

    fun getUserPermissions(authentication: Authentication): List<String> {
        return authentication.authorities.map { it.authority }
    }
}
