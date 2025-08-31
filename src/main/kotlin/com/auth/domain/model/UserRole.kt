package com.auth.domain.model

import jakarta.persistence.Entity
import jakarta.persistence.Id
import jakarta.persistence.Table
import java.util.UUID

@Entity
@Table(name = "user_roles")
data class UserRole(
    @Id
    val id: UUID = UUID.randomUUID(),
    val userId: UUID,
    val roleId: UUID
)