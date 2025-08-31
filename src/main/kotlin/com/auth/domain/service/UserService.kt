package com.auth.domain.service

import com.auth.domain.model.User
import com.auth.infrastructure.persistence.RoleRepo
import com.auth.infrastructure.persistence.UserRepo
import com.auth.infrastructure.persistence.UserRolePermissionGeneralModelRepo
import jakarta.transaction.Transactional
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Service
import java.util.UUID

@Service
class UserService(
    private val users: UserRepo,
    private val roles: RoleRepo,
    private val userRolePermissionGeneralModelRepo: UserRolePermissionGeneralModelRepo,
    private val passwordEncoder: PasswordEncoder,
) {
    @Transactional
    fun create(
        email: String,
        rawPassword: String,
        roleIds: Set<UUID>,
    ): User {
        val u = User(email = email, password = passwordEncoder.encode(rawPassword))
        return users.save(u)
    }

    fun byEmail(email: String) = users.findByEmailIgnoreCase(email)

    fun permissionsOf(u: User): Set<String> =
        userRolePermissionGeneralModelRepo.findByEmailIgnoreCase(u.email)
            .map { r -> r.permissionName }.toSet()

    @Transactional
    fun createUser(
        email: String,
        password: String,
        username: String? = null,
    ): User {
        // Check if user already exists
        if (users.findByEmailIgnoreCase(email).isPresent) {
            throw IllegalArgumentException("User with email $email already exists")
        }
        roles.findByNameIgnoreCase("USER")
            .orElseThrow { IllegalArgumentException("Default USER role not found") }
        val user =
            User(
                email = email,
                username = username,
                password = passwordEncoder.encode(password),
                enabled = true,
            )

        return users.save(user)
    }

    @Transactional
    fun updateUsername(
        email: String,
        newUsername: String,
    ): User {
        val user =
            users.findByEmailIgnoreCase(email)
                .orElseThrow { IllegalArgumentException("User not found with email: $email") }

        val updatedUser = user.copy(username = newUsername)
        return users.save(updatedUser)
    }
}
