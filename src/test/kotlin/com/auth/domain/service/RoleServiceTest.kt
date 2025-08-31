package com.auth.domain.service

import com.auth.common.TestDataFactory
import com.auth.infrastructure.persistence.RoleRepo
import io.mockk.Runs
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.verify
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.util.Optional
import java.util.UUID
import kotlin.test.assertEquals

class RoleServiceTest {
    private val roleRepo = mockk<RoleRepo>()
    private lateinit var roleService: RoleService

    @BeforeEach
    fun setup() {
        clearAllMocks()
        roleService = RoleService(roleRepo)
    }

    @Test
    fun `createRole should create role when name does not exist`() {
        // Given
        val roleName = "ADMIN"
        val savedRole = TestDataFactory.createRole(name = roleName)

        every { roleRepo.existsByNameIgnoreCase(roleName) } returns false
        every { roleRepo.save(any()) } returns savedRole

        // When
        val result = roleService.createRole(roleName)

        // Then
        assertEquals(savedRole, result)
        verify { roleRepo.existsByNameIgnoreCase(roleName) }
        verify {
            roleRepo.save(
                match {
                    it.name == roleName &&
                        it.createdAt != null &&
                        it.updatedAt != null
                },
            )
        }
    }

    @Test
    fun `createRole should throw exception when name already exists`() {
        // Given
        val roleName = "EXISTING_ROLE"

        every { roleRepo.existsByNameIgnoreCase(roleName) } returns true

        // When & Then
        val exception =
            assertThrows<IllegalArgumentException> {
                roleService.createRole(roleName)
            }

        assertEquals("Role with name '$roleName' already exists", exception.message)
        verify { roleRepo.existsByNameIgnoreCase(roleName) }
        verify(exactly = 0) { roleRepo.save(any()) }
    }

    @Test
    fun `getAllRoles should return all roles`() {
        // Given
        val roles =
            listOf(
                TestDataFactory.createRole(name = "ADMIN"),
                TestDataFactory.createRole(name = "USER"),
                TestDataFactory.createRole(name = "MODERATOR"),
            )

        every { roleRepo.findAll() } returns roles

        // When
        val result = roleService.getAllRoles()

        // Then
        assertEquals(roles, result)
        verify { roleRepo.findAll() }
    }

    @Test
    fun `getRoleById should return role when found`() {
        // Given
        val roleId = UUID.randomUUID()
        val role = TestDataFactory.createRole(id = roleId, name = "ADMIN")

        every { roleRepo.findById(roleId) } returns Optional.of(role)

        // When
        val result = roleService.getRoleById(roleId)

        // Then
        assertEquals(role, result)
        verify { roleRepo.findById(roleId) }
    }

    @Test
    fun `getRoleById should throw exception when not found`() {
        // Given
        val roleId = UUID.randomUUID()

        every { roleRepo.findById(roleId) } returns Optional.empty()

        // When & Then
        val exception =
            assertThrows<IllegalArgumentException> {
                roleService.getRoleById(roleId)
            }

        assertEquals("Role not found with ID: $roleId", exception.message)
        verify { roleRepo.findById(roleId) }
    }

    @Test
    fun `getRoleByName should return role when found`() {
        // Given
        val roleName = "ADMIN"
        val role = TestDataFactory.createRole(name = roleName)

        every { roleRepo.findByNameIgnoreCase(roleName) } returns Optional.of(role)

        // When
        val result = roleService.getRoleByName(roleName)

        // Then
        assertEquals(role, result)
        verify { roleRepo.findByNameIgnoreCase(roleName) }
    }

    @Test
    fun `getRoleByName should throw exception when not found`() {
        // Given
        val roleName = "NONEXISTENT"

        every { roleRepo.findByNameIgnoreCase(roleName) } returns Optional.empty()

        // When & Then
        val exception =
            assertThrows<IllegalArgumentException> {
                roleService.getRoleByName(roleName)
            }

        assertEquals("Role not found with name: $roleName", exception.message)
        verify { roleRepo.findByNameIgnoreCase(roleName) }
    }

    @Test
    fun `updateRole should update role when found and new name is available`() {
        // Given
        val roleId = UUID.randomUUID()
        val oldName = "OLD_ROLE"
        val newName = "NEW_ROLE"
        val existingRole = TestDataFactory.createRole(id = roleId, name = oldName)
        val updatedRole = existingRole.copy(name = newName)

        every { roleRepo.findById(roleId) } returns Optional.of(existingRole)
        every { roleRepo.existsByNameIgnoreCase(newName) } returns false
        every { roleRepo.save(any()) } returns updatedRole

        // When
        val result = roleService.updateRole(roleId, newName)

        // Then
        assertEquals(updatedRole, result)
        verify { roleRepo.findById(roleId) }
        verify { roleRepo.existsByNameIgnoreCase(newName) }
        verify {
            roleRepo.save(
                match {
                    it.id == roleId &&
                        it.name == newName &&
                        it.updatedAt != null
                },
            )
        }
    }

    @Test
    fun `updateRole should allow updating to same name`() {
        // Given
        val roleId = UUID.randomUUID()
        val roleName = "SAME_ROLE"
        val existingRole = TestDataFactory.createRole(id = roleId, name = roleName)
        val updatedRole = existingRole.copy()

        every { roleRepo.findById(roleId) } returns Optional.of(existingRole)
        every { roleRepo.existsByNameIgnoreCase(roleName) } returns true
        every { roleRepo.save(any()) } returns updatedRole

        // When
        val result = roleService.updateRole(roleId, roleName)

        // Then
        assertEquals(updatedRole, result)
        verify { roleRepo.findById(roleId) }
        verify { roleRepo.existsByNameIgnoreCase(roleName) }
        verify { roleRepo.save(any()) }
    }

    @Test
    fun `updateRole should throw exception when role not found`() {
        // Given
        val roleId = UUID.randomUUID()
        val newName = "NEW_ROLE"

        every { roleRepo.findById(roleId) } returns Optional.empty()

        // When & Then
        val exception =
            assertThrows<IllegalArgumentException> {
                roleService.updateRole(roleId, newName)
            }

        assertEquals("Role not found with ID: $roleId", exception.message)
        verify { roleRepo.findById(roleId) }
        verify(exactly = 0) { roleRepo.save(any()) }
    }

    @Test
    fun `updateRole should throw exception when new name already exists`() {
        // Given
        val roleId = UUID.randomUUID()
        val oldName = "OLD_ROLE"
        val newName = "EXISTING_ROLE"
        val existingRole = TestDataFactory.createRole(id = roleId, name = oldName)

        every { roleRepo.findById(roleId) } returns Optional.of(existingRole)
        every { roleRepo.existsByNameIgnoreCase(newName) } returns true

        // When & Then
        val exception =
            assertThrows<IllegalArgumentException> {
                roleService.updateRole(roleId, newName)
            }

        assertEquals("Role with name '$newName' already exists", exception.message)
        verify { roleRepo.findById(roleId) }
        verify { roleRepo.existsByNameIgnoreCase(newName) }
        verify(exactly = 0) { roleRepo.save(any()) }
    }

    @Test
    fun `deleteRole should delete role when found`() {
        // Given
        val roleId = UUID.randomUUID()

        every { roleRepo.existsById(roleId) } returns true
        every { roleRepo.deleteById(roleId) } just Runs

        // When
        roleService.deleteRole(roleId)

        // Then
        verify { roleRepo.existsById(roleId) }
        verify { roleRepo.deleteById(roleId) }
    }

    @Test
    fun `deleteRole should throw exception when role not found`() {
        // Given
        val roleId = UUID.randomUUID()

        every { roleRepo.existsById(roleId) } returns false

        // When & Then
        val exception =
            assertThrows<IllegalArgumentException> {
                roleService.deleteRole(roleId)
            }

        assertEquals("Role not found with ID: $roleId", exception.message)
        verify { roleRepo.existsById(roleId) }
        verify(exactly = 0) { roleRepo.deleteById(any()) }
    }
}
