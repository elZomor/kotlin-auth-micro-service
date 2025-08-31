package com.auth.infrastructure.security

object Permissions {
    // Role permissions
    const val ROLE_CREATE = "ROLE_CREATE"
    const val ROLE_READ = "ROLE_READ"
    const val ROLE_UPDATE = "ROLE_UPDATE"
    const val ROLE_DELETE = "ROLE_DELETE"

    // Permission permissions
    const val PERMISSION_CREATE = "PERMISSION_CREATE"
    const val PERMISSION_READ = "PERMISSION_READ"
    const val PERMISSION_UPDATE = "PERMISSION_UPDATE"
    const val PERMISSION_DELETE = "PERMISSION_DELETE"

    // User-Role assignment permissions
    const val USER_ROLE_ASSIGN = "USER_ROLE_ASSIGN"
    const val USER_ROLE_REMOVE = "USER_ROLE_REMOVE"
    const val USER_ROLE_READ = "USER_ROLE_READ"

    // User management permissions
    const val USER_READ = "USER_READ"
    const val USER_UPDATE = "USER_UPDATE"
    const val USER_DELETE = "USER_DELETE"

    // Admin permissions
    const val ADMIN_ACCESS = "ADMIN_ACCESS"
}
