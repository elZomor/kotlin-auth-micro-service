package com.auth.domain.model

import jakarta.persistence.Entity
import jakarta.persistence.Id
import jakarta.persistence.Table
import java.time.OffsetDateTime
import java.util.*

@Entity
@Table(name = "users")
data class User(
    @Id
    val id: UUID = UUID.randomUUID(),
    val email: String,
    val username: String? = null,
    val password: String,
    val enabled: Boolean = true,
    val createdAt: OffsetDateTime? = null,
    val updatedAt: OffsetDateTime? = null
)