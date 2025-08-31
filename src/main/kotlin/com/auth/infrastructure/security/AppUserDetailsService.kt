package com.auth.infrastructure.security

import com.auth.infrastructure.persistence.UserRepo
import com.auth.infrastructure.persistence.UserRolePermissionGeneralModelRepo
import org.slf4j.LoggerFactory
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.stereotype.Service

@Service
class AppUserDetailsService(
    private val userRolePermissionGeneralModelRepo: UserRolePermissionGeneralModelRepo,
    private val userRepo: UserRepo,
) : UserDetailsService {
    private val logger = LoggerFactory.getLogger(AppUserDetailsService::class.java)

    override fun loadUserByUsername(email: String): UserDetails {
        logger.info("Loading user by username: $email")

        val user =
            userRepo.findByEmailIgnoreCase(email).orElseThrow {
                logger.error("User not found: $email")
                UsernameNotFoundException("User not found: $email")
            }

        logger.info("User found: ${user.email}, enabled: ${user.enabled}")
        logger.debug("User password hash: ${user.password}")

        val userRolePermissionGeneralModel = userRolePermissionGeneralModelRepo.findByEmailIgnoreCase(email)
        val permissions =
            userRolePermissionGeneralModel
                .map { userRole -> userRole.permissionName }
                .toSet()
                .map { SimpleGrantedAuthority(it) }

        logger.info("User permissions: ${permissions.map { it.authority }}")

        return User
            .withUsername(email)
            .password(user.password)
            .authorities(permissions)
            .accountExpired(false).accountLocked(false)
            .credentialsExpired(false).disabled(!user.enabled)
            .build()
    }
}
