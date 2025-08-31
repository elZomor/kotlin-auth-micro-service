package com.auth.domain.model

import jakarta.persistence.Entity
import jakarta.persistence.Id
import jakarta.persistence.Table
import java.time.OffsetDateTime
import java.util.*

@Entity
@Table(name = "permissions")
data class Permission(
    @Id
    val id: UUID = UUID.randomUUID(),
    val name: String,
    val createdAt: OffsetDateTime? = null,
    val updatedAt: OffsetDateTime? = null
)