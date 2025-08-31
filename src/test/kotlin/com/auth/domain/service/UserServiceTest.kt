package com.auth.domain.service

import com.auth.common.TestDataFactory
import com.auth.domain.model.User
import com.auth.infrastructure.persistence.RoleRepo
import com.auth.infrastructure.persistence.UserRepo
import com.auth.infrastructure.persistence.UserRolePermissionGeneralModelRepo
import io.mockk.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.springframework.security.crypto.password.PasswordEncoder
import java.util.*
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class UserServiceTest {

    private val userRepo = mockk<UserRepo>()
    private val roleRepo = mockk<RoleRepo>()
    private val userRolePermissionRepo = mockk<UserRolePermissionGeneralModelRepo>()
    private val passwordEncoder = mockk<PasswordEncoder>()
    
    private lateinit var userService: UserService

    @BeforeEach
    fun setup() {
        clearAllMocks()
        userService = UserService(userRepo, roleRepo, userRolePermissionRepo, passwordEncoder)
    }

    @Test
    fun `create should create user with encoded password`() {
        // Given
        val email = "test@example.com"
        val rawPassword = "password123"
        val encodedPassword = "encodedPassword"
        val roleIds = setOf<UUID>()
        val savedUser = TestDataFactory.createUser(email = email, password = encodedPassword)

        every { passwordEncoder.encode(rawPassword) } returns encodedPassword
        every { userRepo.save(any()) } returns savedUser

        // When
        val result = userService.create(email, rawPassword, roleIds)

        // Then
        assertEquals(savedUser, result)
        verify { passwordEncoder.encode(rawPassword) }
        verify { userRepo.save(match { it.email == email && it.password == encodedPassword }) }
    }

    @Test
    fun `byEmail should return user when found`() {
        // Given
        val email = "test@example.com"
        val user = TestDataFactory.createUser(email = email)

        every { userRepo.findByEmailIgnoreCase(email) } returns Optional.of(user)

        // When
        val result = userService.byEmail(email)

        // Then
        assertTrue(result.isPresent)
        assertEquals(user, result.get())
        verify { userRepo.findByEmailIgnoreCase(email) }
    }

    @Test
    fun `byEmail should return empty when not found`() {
        // Given
        val email = "notfound@example.com"

        every { userRepo.findByEmailIgnoreCase(email) } returns Optional.empty()

        // When
        val result = userService.byEmail(email)

        // Then
        assertTrue(result.isEmpty)
        verify { userRepo.findByEmailIgnoreCase(email) }
    }

    @Test
    fun `permissionsOf should return user permissions`() {
        // Given
        val user = TestDataFactory.createUser(email = "test@example.com")
        val permissions = listOf(
            mockk { every { permissionName } returns "READ_USER" },
            mockk { every { permissionName } returns "WRITE_USER" }
        )

        every { userRolePermissionRepo.findByEmailIgnoreCase(user.email) } returns permissions

        // When
        val result = userService.permissionsOf(user)

        // Then
        assertEquals(setOf("READ_USER", "WRITE_USER"), result)
        verify { userRolePermissionRepo.findByEmailIgnoreCase(user.email) }
    }

    @Test
    fun `createUser should create user with default role when user does not exist`() {
        // Given
        val email = "newuser@example.com"
        val password = "password123"
        val username = "newuser"
        val encodedPassword = "encodedPassword"
        val defaultRole = TestDataFactory.createRole(name = "USER")
        val savedUser = TestDataFactory.createUser(email = email, username = username, password = encodedPassword)

        every { userRepo.findByEmailIgnoreCase(email) } returns Optional.empty()
        every { passwordEncoder.encode(password) } returns encodedPassword
        every { roleRepo.findByNameIgnoreCase("USER") } returns Optional.of(defaultRole)
        every { userRepo.save(any()) } returns savedUser

        // When
        val result = userService.createUser(email, password, username)

        // Then
        assertEquals(savedUser, result)
        verify { userRepo.findByEmailIgnoreCase(email) }
        verify { passwordEncoder.encode(password) }
        verify { roleRepo.findByNameIgnoreCase("USER") }
        verify { userRepo.save(match { 
            it.email == email && 
            it.username == username && 
            it.password == encodedPassword &&
            it.enabled == true 
        }) }
    }

    @Test
    fun `createUser should throw exception when user already exists`() {
        // Given
        val email = "existing@example.com"
        val password = "password123"
        val existingUser = TestDataFactory.createUser(email = email)

        every { userRepo.findByEmailIgnoreCase(email) } returns Optional.of(existingUser)

        // When & Then
        val exception = assertThrows<IllegalArgumentException> {
            userService.createUser(email, password)
        }

        assertEquals("User with email $email already exists", exception.message)
        verify { userRepo.findByEmailIgnoreCase(email) }
        verify(exactly = 0) { userRepo.save(any()) }
    }

    @Test
    fun `createUser should throw exception when default role not found`() {
        // Given
        val email = "newuser@example.com"
        val password = "password123"

        every { userRepo.findByEmailIgnoreCase(email) } returns Optional.empty()
        every { roleRepo.findByNameIgnoreCase("USER") } returns Optional.empty()

        // When & Then
        val exception = assertThrows<IllegalArgumentException> {
            userService.createUser(email, password)
        }

        assertEquals("Default USER role not found", exception.message)
        verify { userRepo.findByEmailIgnoreCase(email) }
        verify { roleRepo.findByNameIgnoreCase("USER") }
        verify(exactly = 0) { userRepo.save(any()) }
    }

    @Test
    fun `updateUsername should update user username when user exists`() {
        // Given
        val email = "test@example.com"
        val oldUsername = "oldusername"
        val newUsername = "newusername"
        val user = TestDataFactory.createUser(email = email, username = oldUsername)
        val updatedUser = user.copy(username = newUsername)

        every { userRepo.findByEmailIgnoreCase(email) } returns Optional.of(user)
        every { userRepo.save(any()) } returns updatedUser

        // When
        val result = userService.updateUsername(email, newUsername)

        // Then
        assertEquals(updatedUser, result)
        assertEquals(newUsername, result.username)
        verify { userRepo.findByEmailIgnoreCase(email) }
        verify { userRepo.save(match { it.username == newUsername }) }
    }

    @Test
    fun `updateUsername should throw exception when user not found`() {
        // Given
        val email = "notfound@example.com"
        val newUsername = "newusername"

        every { userRepo.findByEmailIgnoreCase(email) } returns Optional.empty()

        // When & Then
        val exception = assertThrows<IllegalArgumentException> {
            userService.updateUsername(email, newUsername)
        }

        assertEquals("User not found with email: $email", exception.message)
        verify { userRepo.findByEmailIgnoreCase(email) }
        verify(exactly = 0) { userRepo.save(any()) }
    }
}