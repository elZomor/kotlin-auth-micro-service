package com.auth.domain.service

import com.auth.common.TestDataFactory
import com.auth.infrastructure.persistence.RoleRepo
import com.auth.infrastructure.persistence.UserRepo
import com.auth.infrastructure.persistence.UserRoleRepo
import io.mockk.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.util.*
import kotlin.test.assertEquals

class UserRoleServiceTest {

    private val userRepo = mockk<UserRepo>()
    private val roleRepo = mockk<RoleRepo>()
    private val userRoleRepo = mockk<UserRoleRepo>()
    private lateinit var userRoleService: UserRoleService

    @BeforeEach
    fun setup() {
        clearAllMocks()
        userRoleService = UserRoleService(userRepo, roleRepo, userRoleRepo)
    }

    @Test
    fun `assignUserToRole should assign user to role when both exist and not already assigned`() {
        // Given
        val userId = UUID.randomUUID()
        val roleId = UUID.randomUUID()
        val user = TestDataFactory.createUser(id = userId, email = "test@example.com")
        val role = TestDataFactory.createRole(id = roleId, name = "ADMIN")
        val userRole = TestDataFactory.createUserRole(userId = userId, roleId = roleId)

        every { userRepo.findById(userId) } returns Optional.of(user)
        every { roleRepo.findById(roleId) } returns Optional.of(role)
        every { userRoleRepo.existsByUserIdAndRoleId(userId, roleId) } returns false
        every { userRoleRepo.save(any()) } returns userRole

        // When
        val result = userRoleService.assignUserToRole(userId, roleId)

        // Then
        assertEquals(userRole, result)
        verify { userRepo.findById(userId) }
        verify { roleRepo.findById(roleId) }
        verify { userRoleRepo.existsByUserIdAndRoleId(userId, roleId) }
        verify { userRoleRepo.save(match { it.userId == userId && it.roleId == roleId }) }
    }

    @Test
    fun `assignUserToRole should throw exception when user not found`() {
        // Given
        val userId = UUID.randomUUID()
        val roleId = UUID.randomUUID()

        every { userRepo.findById(userId) } returns Optional.empty()

        // When & Then
        val exception = assertThrows<IllegalArgumentException> {
            userRoleService.assignUserToRole(userId, roleId)
        }

        assertEquals("User not found with ID: $userId", exception.message)
        verify { userRepo.findById(userId) }
        verify(exactly = 0) { roleRepo.findById(any()) }
        verify(exactly = 0) { userRoleRepo.save(any()) }
    }

    @Test
    fun `assignUserToRole should throw exception when role not found`() {
        // Given
        val userId = UUID.randomUUID()
        val roleId = UUID.randomUUID()
        val user = TestDataFactory.createUser(id = userId)

        every { userRepo.findById(userId) } returns Optional.of(user)
        every { roleRepo.findById(roleId) } returns Optional.empty()

        // When & Then
        val exception = assertThrows<IllegalArgumentException> {
            userRoleService.assignUserToRole(userId, roleId)
        }

        assertEquals("Role not found with ID: $roleId", exception.message)
        verify { userRepo.findById(userId) }
        verify { roleRepo.findById(roleId) }
        verify(exactly = 0) { userRoleRepo.save(any()) }
    }

    @Test
    fun `assignUserToRole should throw exception when assignment already exists`() {
        // Given
        val userId = UUID.randomUUID()
        val roleId = UUID.randomUUID()
        val user = TestDataFactory.createUser(id = userId)
        val role = TestDataFactory.createRole(id = roleId)

        every { userRepo.findById(userId) } returns Optional.of(user)
        every { roleRepo.findById(roleId) } returns Optional.of(role)
        every { userRoleRepo.existsByUserIdAndRoleId(userId, roleId) } returns true

        // When & Then
        val exception = assertThrows<IllegalArgumentException> {
            userRoleService.assignUserToRole(userId, roleId)
        }

        assertEquals("User $userId is already assigned to role $roleId", exception.message)
        verify { userRepo.findById(userId) }
        verify { roleRepo.findById(roleId) }
        verify { userRoleRepo.existsByUserIdAndRoleId(userId, roleId) }
        verify(exactly = 0) { userRoleRepo.save(any()) }
    }

    @Test
    fun `removeUserFromRole should remove user from role when assignment exists`() {
        // Given
        val userId = UUID.randomUUID()
        val roleId = UUID.randomUUID()

        every { userRoleRepo.existsByUserIdAndRoleId(userId, roleId) } returns true
        every { userRoleRepo.deleteByUserIdAndRoleId(userId, roleId) } just Runs

        // When
        userRoleService.removeUserFromRole(userId, roleId)

        // Then
        verify { userRoleRepo.existsByUserIdAndRoleId(userId, roleId) }
        verify { userRoleRepo.deleteByUserIdAndRoleId(userId, roleId) }
    }

    @Test
    fun `removeUserFromRole should throw exception when assignment does not exist`() {
        // Given
        val userId = UUID.randomUUID()
        val roleId = UUID.randomUUID()

        every { userRoleRepo.existsByUserIdAndRoleId(userId, roleId) } returns false

        // When & Then
        val exception = assertThrows<IllegalArgumentException> {
            userRoleService.removeUserFromRole(userId, roleId)
        }

        assertEquals("User $userId is not assigned to role $roleId", exception.message)
        verify { userRoleRepo.existsByUserIdAndRoleId(userId, roleId) }
        verify(exactly = 0) { userRoleRepo.deleteByUserIdAndRoleId(any(), any()) }
    }

    @Test
    fun `getUserRoles should return all roles for user`() {
        // Given
        val userId = UUID.randomUUID()
        val userRoles = listOf(
            TestDataFactory.createUserRole(userId = userId, roleId = UUID.randomUUID()),
            TestDataFactory.createUserRole(userId = userId, roleId = UUID.randomUUID())
        )

        every { userRoleRepo.findByUserId(userId) } returns userRoles

        // When
        val result = userRoleService.getUserRoles(userId)

        // Then
        assertEquals(userRoles, result)
        verify { userRoleRepo.findByUserId(userId) }
    }

    @Test
    fun `getRoleUsers should return all users for role`() {
        // Given
        val roleId = UUID.randomUUID()
        val userRoles = listOf(
            TestDataFactory.createUserRole(userId = UUID.randomUUID(), roleId = roleId),
            TestDataFactory.createUserRole(userId = UUID.randomUUID(), roleId = roleId)
        )

        every { userRoleRepo.findByRoleId(roleId) } returns userRoles

        // When
        val result = userRoleService.getRoleUsers(roleId)

        // Then
        assertEquals(userRoles, result)
        verify { userRoleRepo.findByRoleId(roleId) }
    }

    @Test
    fun `getUserRoles should return empty list when user has no roles`() {
        // Given
        val userId = UUID.randomUUID()

        every { userRoleRepo.findByUserId(userId) } returns emptyList()

        // When
        val result = userRoleService.getUserRoles(userId)

        // Then
        assertEquals(emptyList(), result)
        verify { userRoleRepo.findByUserId(userId) }
    }

    @Test
    fun `getRoleUsers should return empty list when role has no users`() {
        // Given
        val roleId = UUID.randomUUID()

        every { userRoleRepo.findByRoleId(roleId) } returns emptyList()

        // When
        val result = userRoleService.getRoleUsers(roleId)

        // Then
        assertEquals(emptyList(), result)
        verify { userRoleRepo.findByRoleId(roleId) }
    }
}