package com.auth.domain.model

import jakarta.persistence.Entity
import jakarta.persistence.Id
import jakarta.persistence.Table
import java.time.OffsetDateTime
import java.util.*

@Entity
@Table(name = "user_roles_generalmodel")
data class UserRolesGeneralModel(
    @Id
    val id:UUID,
    val email: String,
    val username: String?,
    val roleName: String
)