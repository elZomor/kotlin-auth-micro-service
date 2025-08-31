package com.auth.domain.service

import com.auth.common.TestDataFactory
import com.auth.infrastructure.persistence.PermissionRepo
import io.mockk.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.util.*
import kotlin.test.assertEquals

class PermissionServiceTest {

    private val permissionRepo = mockk<PermissionRepo>()
    private lateinit var permissionService: PermissionService

    @BeforeEach
    fun setup() {
        clearAllMocks()
        permissionService = PermissionService(permissionRepo)
    }

    @Test
    fun `createPermission should create permission when name does not exist`() {
        // Given
        val permissionName = "READ_USER"
        val savedPermission = TestDataFactory.createPermission(name = permissionName)

        every { permissionRepo.existsByNameIgnoreCase(permissionName) } returns false
        every { permissionRepo.save(any()) } returns savedPermission

        // When
        val result = permissionService.createPermission(permissionName)

        // Then
        assertEquals(savedPermission, result)
        verify { permissionRepo.existsByNameIgnoreCase(permissionName) }
        verify { permissionRepo.save(match { 
            it.name == permissionName && 
            it.createdAt != null && 
            it.updatedAt != null 
        }) }
    }

    @Test
    fun `createPermission should throw exception when name already exists`() {
        // Given
        val permissionName = "EXISTING_PERMISSION"

        every { permissionRepo.existsByNameIgnoreCase(permissionName) } returns true

        // When & Then
        val exception = assertThrows<IllegalArgumentException> {
            permissionService.createPermission(permissionName)
        }

        assertEquals("Permission with name '$permissionName' already exists", exception.message)
        verify { permissionRepo.existsByNameIgnoreCase(permissionName) }
        verify(exactly = 0) { permissionRepo.save(any()) }
    }

    @Test
    fun `getAllPermissions should return all permissions`() {
        // Given
        val permissions = listOf(
            TestDataFactory.createPermission(name = "READ_USER"),
            TestDataFactory.createPermission(name = "WRITE_USER"),
            TestDataFactory.createPermission(name = "DELETE_USER")
        )

        every { permissionRepo.findAll() } returns permissions

        // When
        val result = permissionService.getAllPermissions()

        // Then
        assertEquals(permissions, result)
        verify { permissionRepo.findAll() }
    }

    @Test
    fun `getPermissionById should return permission when found`() {
        // Given
        val permissionId = UUID.randomUUID()
        val permission = TestDataFactory.createPermission(id = permissionId, name = "READ_USER")

        every { permissionRepo.findById(permissionId) } returns Optional.of(permission)

        // When
        val result = permissionService.getPermissionById(permissionId)

        // Then
        assertEquals(permission, result)
        verify { permissionRepo.findById(permissionId) }
    }

    @Test
    fun `getPermissionById should throw exception when not found`() {
        // Given
        val permissionId = UUID.randomUUID()

        every { permissionRepo.findById(permissionId) } returns Optional.empty()

        // When & Then
        val exception = assertThrows<IllegalArgumentException> {
            permissionService.getPermissionById(permissionId)
        }

        assertEquals("Permission not found with ID: $permissionId", exception.message)
        verify { permissionRepo.findById(permissionId) }
    }

    @Test
    fun `getPermissionByName should return permission when found`() {
        // Given
        val permissionName = "READ_USER"
        val permission = TestDataFactory.createPermission(name = permissionName)

        every { permissionRepo.findByNameIgnoreCase(permissionName) } returns Optional.of(permission)

        // When
        val result = permissionService.getPermissionByName(permissionName)

        // Then
        assertEquals(permission, result)
        verify { permissionRepo.findByNameIgnoreCase(permissionName) }
    }

    @Test
    fun `getPermissionByName should throw exception when not found`() {
        // Given
        val permissionName = "NONEXISTENT"

        every { permissionRepo.findByNameIgnoreCase(permissionName) } returns Optional.empty()

        // When & Then
        val exception = assertThrows<IllegalArgumentException> {
            permissionService.getPermissionByName(permissionName)
        }

        assertEquals("Permission not found with name: $permissionName", exception.message)
        verify { permissionRepo.findByNameIgnoreCase(permissionName) }
    }

    @Test
    fun `updatePermission should update permission when found and new name is available`() {
        // Given
        val permissionId = UUID.randomUUID()
        val oldName = "OLD_PERMISSION"
        val newName = "NEW_PERMISSION"
        val existingPermission = TestDataFactory.createPermission(id = permissionId, name = oldName)
        val updatedPermission = existingPermission.copy(name = newName)

        every { permissionRepo.findById(permissionId) } returns Optional.of(existingPermission)
        every { permissionRepo.existsByNameIgnoreCase(newName) } returns false
        every { permissionRepo.save(any()) } returns updatedPermission

        // When
        val result = permissionService.updatePermission(permissionId, newName)

        // Then
        assertEquals(updatedPermission, result)
        verify { permissionRepo.findById(permissionId) }
        verify { permissionRepo.existsByNameIgnoreCase(newName) }
        verify { permissionRepo.save(match { 
            it.id == permissionId && 
            it.name == newName && 
            it.updatedAt != null 
        }) }
    }

    @Test
    fun `updatePermission should allow updating to same name`() {
        // Given
        val permissionId = UUID.randomUUID()
        val permissionName = "SAME_PERMISSION"
        val existingPermission = TestDataFactory.createPermission(id = permissionId, name = permissionName)
        val updatedPermission = existingPermission.copy()

        every { permissionRepo.findById(permissionId) } returns Optional.of(existingPermission)
        every { permissionRepo.existsByNameIgnoreCase(permissionName) } returns true
        every { permissionRepo.save(any()) } returns updatedPermission

        // When
        val result = permissionService.updatePermission(permissionId, permissionName)

        // Then
        assertEquals(updatedPermission, result)
        verify { permissionRepo.findById(permissionId) }
        verify { permissionRepo.existsByNameIgnoreCase(permissionName) }
        verify { permissionRepo.save(any()) }
    }

    @Test
    fun `updatePermission should throw exception when permission not found`() {
        // Given
        val permissionId = UUID.randomUUID()
        val newName = "NEW_PERMISSION"

        every { permissionRepo.findById(permissionId) } returns Optional.empty()

        // When & Then
        val exception = assertThrows<IllegalArgumentException> {
            permissionService.updatePermission(permissionId, newName)
        }

        assertEquals("Permission not found with ID: $permissionId", exception.message)
        verify { permissionRepo.findById(permissionId) }
        verify(exactly = 0) { permissionRepo.save(any()) }
    }

    @Test
    fun `updatePermission should throw exception when new name already exists`() {
        // Given
        val permissionId = UUID.randomUUID()
        val oldName = "OLD_PERMISSION"
        val newName = "EXISTING_PERMISSION"
        val existingPermission = TestDataFactory.createPermission(id = permissionId, name = oldName)

        every { permissionRepo.findById(permissionId) } returns Optional.of(existingPermission)
        every { permissionRepo.existsByNameIgnoreCase(newName) } returns true

        // When & Then
        val exception = assertThrows<IllegalArgumentException> {
            permissionService.updatePermission(permissionId, newName)
        }

        assertEquals("Permission with name '$newName' already exists", exception.message)
        verify { permissionRepo.findById(permissionId) }
        verify { permissionRepo.existsByNameIgnoreCase(newName) }
        verify(exactly = 0) { permissionRepo.save(any()) }
    }

    @Test
    fun `deletePermission should delete permission when found`() {
        // Given
        val permissionId = UUID.randomUUID()

        every { permissionRepo.existsById(permissionId) } returns true
        every { permissionRepo.deleteById(permissionId) } just Runs

        // When
        permissionService.deletePermission(permissionId)

        // Then
        verify { permissionRepo.existsById(permissionId) }
        verify { permissionRepo.deleteById(permissionId) }
    }

    @Test
    fun `deletePermission should throw exception when permission not found`() {
        // Given
        val permissionId = UUID.randomUUID()

        every { permissionRepo.existsById(permissionId) } returns false

        // When & Then
        val exception = assertThrows<IllegalArgumentException> {
            permissionService.deletePermission(permissionId)
        }

        assertEquals("Permission not found with ID: $permissionId", exception.message)
        verify { permissionRepo.existsById(permissionId) }
        verify(exactly = 0) { permissionRepo.deleteById(any()) }
    }
}