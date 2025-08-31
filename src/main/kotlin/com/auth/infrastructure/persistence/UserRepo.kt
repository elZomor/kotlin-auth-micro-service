package com.auth.infrastructure.persistence

import com.auth.domain.model.User
import org.springframework.data.jpa.repository.JpaRepository
import java.util.Optional
import java.util.UUID

interface UserRepo : JpaRepository<User, UUID> {
    fun findByEmailIgnoreCase(email: String): Optional<User>

    fun findByUsernameIgnoreCase(username: String): Optional<User>
}
