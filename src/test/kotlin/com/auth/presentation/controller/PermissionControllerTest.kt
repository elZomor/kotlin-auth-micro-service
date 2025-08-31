package com.auth.presentation.controller

import com.auth.common.TestDataFactory
import com.auth.domain.model.Permission
import com.auth.domain.service.PermissionService
import com.auth.infrastructure.security.AuthorizationUtils
import com.auth.infrastructure.security.Permissions
import com.auth.presentation.dto.CreatePermissionRequest
import com.fasterxml.jackson.databind.ObjectMapper
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.http.MediaType
import org.springframework.security.core.Authentication
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import org.springframework.test.web.servlet.setup.MockMvcBuilders
import java.util.UUID

class PermissionControllerTest {
    private val permissionService = mockk<PermissionService>(relaxed = true)
    private val authorizationUtils = mockk<AuthorizationUtils>(relaxed = true)

    private lateinit var permissionController: PermissionController
    private lateinit var mockMvc: MockMvc
    private val objectMapper = ObjectMapper()

    @BeforeEach
    fun setup() {
        clearAllMocks()
        permissionController = PermissionController(permissionService, authorizationUtils)
        mockMvc = MockMvcBuilders.standaloneSetup(permissionController).build()
    }

    @Test
    fun `createPermission should create permission successfully when user has permission`() {
        // Given
        val createRequest = TestDataFactory.createCreatePermissionRequest("CREATE_USER")
        val createdPermission = TestDataFactory.createPermission(name = "CREATE_USER")
        val authentication = mockk<Authentication>()
        val authorities = listOf(SimpleGrantedAuthority(Permissions.PERMISSION_CREATE))

        every { authentication.name } returns "admin@example.com"
        every { authentication.authorities } returns authorities
        every { authorizationUtils.hasPermission(authentication, Permissions.PERMISSION_CREATE) } returns true
        every { permissionService.createPermission("CREATE_USER") } returns createdPermission

        // When & Then
        mockMvc.perform(
            post("/admin/permissions")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(createRequest))
                .principal(authentication)
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.message").value("Permission created successfully"))
            .andExpect(jsonPath("$.permission.id").value(createdPermission.id.toString()))
            .andExpect(jsonPath("$.permission.name").value("CREATE_USER"))

        verify { permissionService.createPermission("CREATE_USER") }
        verify { authorizationUtils.hasPermission(authentication, Permissions.PERMISSION_CREATE) }
    }

    @Test
    fun `createPermission should return forbidden when user lacks permission`() {
        // Given
        val createRequest = TestDataFactory.createCreatePermissionRequest("CREATE_USER")
        val authentication = mockk<Authentication>()

        every { authentication.name } returns "user@example.com"
        every { authorizationUtils.hasPermission(authentication, Permissions.PERMISSION_CREATE) } returns false

        // When & Then
        mockMvc.perform(
            post("/admin/permissions")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(createRequest))
                .principal(authentication)
        )
            .andExpect(status().isForbidden)
            .andExpect(jsonPath("$.error").value("Insufficient permissions. Required: ${Permissions.PERMISSION_CREATE}"))

        verify { authorizationUtils.hasPermission(authentication, Permissions.PERMISSION_CREATE) }
        verify(exactly = 0) { permissionService.createPermission(any()) }
    }

    @Test
    fun `createPermission should return bad request when service throws exception`() {
        // Given
        val createRequest = TestDataFactory.createCreatePermissionRequest("CREATE_USER")
        val authentication = mockk<Authentication>()
        val authorities = listOf(SimpleGrantedAuthority(Permissions.PERMISSION_CREATE))

        every { authentication.name } returns "admin@example.com"
        every { authentication.authorities } returns authorities
        every { authorizationUtils.hasPermission(authentication, Permissions.PERMISSION_CREATE) } returns true
        every { permissionService.createPermission("CREATE_USER") } throws IllegalArgumentException("Permission already exists")

        // When & Then
        mockMvc.perform(
            post("/admin/permissions")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(createRequest))
                .principal(authentication)
        )
            .andExpect(status().isBadRequest)
            .andExpect(jsonPath("$.error").value("Illegal Exception: Permission already exists"))

        verify { permissionService.createPermission("CREATE_USER") }
    }

    @Test
    fun `getAllPermissions should return all permissions when user has permission`() {
        // Given
        val permissions = listOf(
            TestDataFactory.createPermission(name = "CREATE_USER"),
            TestDataFactory.createPermission(name = "READ_USER")
        )
        val authentication = mockk<Authentication>()
        val authorities = listOf(SimpleGrantedAuthority(Permissions.PERMISSION_READ))

        every { authentication.name } returns "admin@example.com"
        every { authentication.authorities } returns authorities
        every { authorizationUtils.hasPermission(authentication, Permissions.PERMISSION_READ) } returns true
        every { permissionService.getAllPermissions() } returns permissions

        // When & Then
        mockMvc.perform(
            get("/admin/permissions")
                .principal(authentication)
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.permissions").isArray)
            .andExpect(jsonPath("$.permissions.length()").value(2))
            .andExpect(jsonPath("$.permissions[0].name").value("CREATE_USER"))
            .andExpect(jsonPath("$.permissions[1].name").value("READ_USER"))

        verify { permissionService.getAllPermissions() }
        verify { authorizationUtils.hasPermission(authentication, Permissions.PERMISSION_READ) }
    }

    @Test
    fun `getAllPermissions should return forbidden when user lacks permission`() {
        // Given
        val authentication = mockk<Authentication>()

        every { authentication.name } returns "user@example.com"
        every { authorizationUtils.hasPermission(authentication, Permissions.PERMISSION_READ) } returns false

        // When & Then
        mockMvc.perform(
            get("/admin/permissions")
                .principal(authentication)
        )
            .andExpect(status().isForbidden)
            .andExpect(jsonPath("$.error").value("Insufficient permissions. Required: ${Permissions.PERMISSION_READ}"))

        verify { authorizationUtils.hasPermission(authentication, Permissions.PERMISSION_READ) }
        verify(exactly = 0) { permissionService.getAllPermissions() }
    }

    @Test
    fun `getPermissionById should return permission when user has permission`() {
        // Given
        val permissionId = UUID.randomUUID()
        val permission = TestDataFactory.createPermission(id = permissionId, name = "CREATE_USER")
        val authentication = mockk<Authentication>()
        val authorities = listOf(SimpleGrantedAuthority(Permissions.PERMISSION_READ))

        every { authentication.name } returns "admin@example.com"
        every { authentication.authorities } returns authorities
        every { authorizationUtils.hasPermission(authentication, Permissions.PERMISSION_READ) } returns true
        every { permissionService.getPermissionById(permissionId) } returns permission

        // When & Then
        mockMvc.perform(
            get("/admin/permissions/$permissionId")
                .principal(authentication)
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.permission.id").value(permissionId.toString()))
            .andExpect(jsonPath("$.permission.name").value("CREATE_USER"))

        verify { permissionService.getPermissionById(permissionId) }
        verify { authorizationUtils.hasPermission(authentication, Permissions.PERMISSION_READ) }
    }

    @Test
    fun `getPermissionById should return forbidden when user lacks permission`() {
        // Given
        val permissionId = UUID.randomUUID()
        val authentication = mockk<Authentication>()

        every { authentication.name } returns "user@example.com"
        every { authorizationUtils.hasPermission(authentication, Permissions.PERMISSION_READ) } returns false

        // When & Then
        mockMvc.perform(
            get("/admin/permissions/$permissionId")
                .principal(authentication)
        )
            .andExpect(status().isForbidden)
            .andExpect(jsonPath("$.error").value("Insufficient permissions. Required: ${Permissions.PERMISSION_READ}"))

        verify { authorizationUtils.hasPermission(authentication, Permissions.PERMISSION_READ) }
        verify(exactly = 0) { permissionService.getPermissionById(any()) }
    }

    @Test
    fun `updatePermission should update permission successfully when user has permission`() {
        // Given
        val permissionId = UUID.randomUUID()
        val updateRequest = TestDataFactory.createCreatePermissionRequest("UPDATE_USER")
        val updatedPermission = TestDataFactory.createPermission(id = permissionId, name = "UPDATE_USER")
        val authentication = mockk<Authentication>()
        val authorities = listOf(SimpleGrantedAuthority(Permissions.PERMISSION_UPDATE))

        every { authentication.name } returns "admin@example.com"
        every { authentication.authorities } returns authorities
        every { authorizationUtils.hasPermission(authentication, Permissions.PERMISSION_UPDATE) } returns true
        every { permissionService.updatePermission(permissionId, "UPDATE_USER") } returns updatedPermission

        // When & Then
        mockMvc.perform(
            put("/admin/permissions/$permissionId")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(updateRequest))
                .principal(authentication)
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.message").value("Permission updated successfully"))
            .andExpect(jsonPath("$.permission.id").value(permissionId.toString()))
            .andExpect(jsonPath("$.permission.name").value("UPDATE_USER"))

        verify { permissionService.updatePermission(permissionId, "UPDATE_USER") }
        verify { authorizationUtils.hasPermission(authentication, Permissions.PERMISSION_UPDATE) }
    }

    @Test
    fun `updatePermission should return forbidden when user lacks permission`() {
        // Given
        val permissionId = UUID.randomUUID()
        val updateRequest = TestDataFactory.createCreatePermissionRequest("UPDATE_USER")
        val authentication = mockk<Authentication>()

        every { authentication.name } returns "user@example.com"
        every { authorizationUtils.hasPermission(authentication, Permissions.PERMISSION_UPDATE) } returns false

        // When & Then
        mockMvc.perform(
            put("/admin/permissions/$permissionId")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(updateRequest))
                .principal(authentication)
        )
            .andExpect(status().isForbidden)
            .andExpect(jsonPath("$.error").value("Insufficient permissions. Required: ${Permissions.PERMISSION_UPDATE}"))

        verify { authorizationUtils.hasPermission(authentication, Permissions.PERMISSION_UPDATE) }
        verify(exactly = 0) { permissionService.updatePermission(any(), any()) }
    }

    @Test
    fun `deletePermission should delete permission successfully when user has permission`() {
        // Given
        val permissionId = UUID.randomUUID()
        val authentication = mockk<Authentication>()
        val authorities = listOf(SimpleGrantedAuthority(Permissions.PERMISSION_DELETE))

        every { authentication.name } returns "admin@example.com"
        every { authentication.authorities } returns authorities
        every { authorizationUtils.hasPermission(authentication, Permissions.PERMISSION_DELETE) } returns true
        every { permissionService.deletePermission(permissionId) } returns Unit

        // When & Then
        mockMvc.perform(
            delete("/admin/permissions/$permissionId")
                .principal(authentication)
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.message").value("Permission deleted successfully"))

        verify { permissionService.deletePermission(permissionId) }
        verify { authorizationUtils.hasPermission(authentication, Permissions.PERMISSION_DELETE) }
    }

    @Test
    fun `deletePermission should return forbidden when user lacks permission`() {
        // Given
        val permissionId = UUID.randomUUID()
        val authentication = mockk<Authentication>()

        every { authentication.name } returns "user@example.com"
        every { authorizationUtils.hasPermission(authentication, Permissions.PERMISSION_DELETE) } returns false

        // When & Then
        mockMvc.perform(
            delete("/admin/permissions/$permissionId")
                .principal(authentication)
        )
            .andExpect(status().isForbidden)
            .andExpect(jsonPath("$.error").value("Insufficient permissions. Required: ${Permissions.PERMISSION_DELETE}"))

        verify { authorizationUtils.hasPermission(authentication, Permissions.PERMISSION_DELETE) }
        verify(exactly = 0) { permissionService.deletePermission(any()) }
    }

    @Test
    fun `createPermission should return bad request for invalid input`() {
        // Given
        val invalidRequest = CreatePermissionRequest(name = "")
        val authentication = mockk<Authentication>()
        val authorities = listOf(SimpleGrantedAuthority(Permissions.PERMISSION_CREATE))

        every { authentication.name } returns "admin@example.com"
        every { authentication.authorities } returns authorities
        every { authorizationUtils.hasPermission(authentication, Permissions.PERMISSION_CREATE) } returns true

        // When & Then
        mockMvc.perform(
            post("/admin/permissions")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(invalidRequest))
                .principal(authentication)
        )
            .andExpect(status().isBadRequest)

        verify(exactly = 0) { permissionService.createPermission(any()) }
    }
}