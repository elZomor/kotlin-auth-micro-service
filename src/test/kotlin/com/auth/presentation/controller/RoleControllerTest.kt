package com.auth.presentation.controller

import com.auth.common.TestDataFactory
import com.auth.domain.service.RoleService
import com.auth.presentation.dto.CreateRoleRequest
import com.auth.infrastructure.security.AuthorizationUtils
import com.fasterxml.jackson.databind.ObjectMapper
import io.mockk.Runs
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.verify
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.http.MediaType
import org.springframework.security.core.context.SecurityContext
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.Authentication
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import org.springframework.test.web.servlet.setup.MockMvcBuilders
import java.util.UUID

class RoleControllerTest {
    private val roleService = mockk<RoleService>(relaxed = true)
    private val authorizationUtils = mockk<AuthorizationUtils>(relaxed = true)
    private lateinit var roleController: RoleController
    private lateinit var mockMvc: MockMvc
    private val objectMapper = ObjectMapper()

    @BeforeEach
    fun setup() {
        clearAllMocks()
        // Mock authorizationUtils to return true for ADMIN users
        every { authorizationUtils.hasPermission(any(), "ADMIN") } returns true
        roleController = RoleController(roleService, authorizationUtils)
        mockMvc = MockMvcBuilders.standaloneSetup(roleController).build()
    }

    private fun setupSecurityContext() {
        val mockSecurityContext = mockk<SecurityContext>()
        val mockAuthentication = mockk<Authentication>()
        SecurityContextHolder.setContext(mockSecurityContext)
        every { mockSecurityContext.authentication } returns mockAuthentication
        every { mockAuthentication.name } returns "admin@example.com"
    }

    @Test
    fun `createRole should create role and return success`() {
        // Given
        val createRequest = TestDataFactory.createCreateRoleRequest("MANAGER")
        val createdRole = TestDataFactory.createRole(name = "MANAGER")
        setupSecurityContext()
        every { roleService.createRole("MANAGER") } returns createdRole

        // When & Then
        mockMvc.perform(
            post("/roles")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(createRequest)),
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.name").value("MANAGER"))
            .andExpect(jsonPath("$.id").value(createdRole.id.toString()))

        verify { roleService.createRole("MANAGER") }
    }

    @Test
    fun `createRole should return bad request when role already exists`() {
        // Given
        val createRequest = TestDataFactory.createCreateRoleRequest("EXISTING_ROLE")
        setupSecurityContext()
        every { roleService.createRole("EXISTING_ROLE") } throws IllegalArgumentException("Role already exists")

        // When & Then
        mockMvc.perform(
            post("/roles")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(createRequest)),
        )
            .andExpect(status().isBadRequest)

        verify { roleService.createRole("EXISTING_ROLE") }
    }

    @Test
    fun `getAllRoles should return list of roles`() {
        // Given
        val roles =
            listOf(
                TestDataFactory.createRole(name = "ADMIN"),
                TestDataFactory.createRole(name = "USER"),
                TestDataFactory.createRole(name = "MODERATOR"),
            )
        setupSecurityContext()
        every { roleService.getAllRoles() } returns roles

        // When & Then
        mockMvc.perform(get("/roles"))
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.length()").value(3))
            .andExpect(jsonPath("$[0].name").value("ADMIN"))
            .andExpect(jsonPath("$[1].name").value("USER"))
            .andExpect(jsonPath("$[2].name").value("MODERATOR"))

        verify { roleService.getAllRoles() }
    }

    @Test
    fun `getAllRoles should return empty list when no roles exist`() {
        // Given
        setupSecurityContext()
        every { roleService.getAllRoles() } returns emptyList()

        // When & Then
        mockMvc.perform(get("/roles"))
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.length()").value(0))

        verify { roleService.getAllRoles() }
    }

    @Test
    fun `getRoleById should return role when found`() {
        // Given
        val roleId = UUID.randomUUID()
        val role = TestDataFactory.createRole(id = roleId, name = "ADMIN")
        setupSecurityContext()
        every { roleService.getRoleById(roleId) } returns role

        // When & Then
        mockMvc.perform(get("/roles/{id}", roleId))
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.id").value(roleId.toString()))
            .andExpect(jsonPath("$.name").value("ADMIN"))

        verify { roleService.getRoleById(roleId) }
    }

    @Test
    fun `getRoleById should return not found when role does not exist`() {
        // Given
        val roleId = UUID.randomUUID()
        setupSecurityContext()
        every { roleService.getRoleById(roleId) } throws IllegalArgumentException("Role not found")

        // When & Then
        mockMvc.perform(get("/roles/{id}", roleId))
            .andExpect(status().isNotFound)

        verify { roleService.getRoleById(roleId) }
    }

    @Test
    fun `updateRole should update role and return success`() {
        // Given
        val roleId = UUID.randomUUID()
        val updateRequest = TestDataFactory.createCreateRoleRequest("UPDATED_ROLE")
        val updatedRole = TestDataFactory.createRole(id = roleId, name = "UPDATED_ROLE")
        setupSecurityContext()
        every { roleService.updateRole(roleId, "UPDATED_ROLE") } returns updatedRole

        // When & Then
        mockMvc.perform(
            put("/roles/{id}", roleId)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(updateRequest)),
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.id").value(roleId.toString()))
            .andExpect(jsonPath("$.name").value("UPDATED_ROLE"))

        verify { roleService.updateRole(roleId, "UPDATED_ROLE") }
    }

    @Test
    fun `updateRole should return not found when role does not exist`() {
        // Given
        val roleId = UUID.randomUUID()
        val updateRequest = TestDataFactory.createCreateRoleRequest("NEW_NAME")
        setupSecurityContext()
        every { roleService.updateRole(roleId, "NEW_NAME") } throws IllegalArgumentException("Role not found")

        // When & Then
        mockMvc.perform(
            put("/roles/{id}", roleId)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(updateRequest)),
        )
            .andExpect(status().isNotFound)

        verify { roleService.updateRole(roleId, "NEW_NAME") }
    }

    @Test
    fun `updateRole should return bad request when new name already exists`() {
        // Given
        val roleId = UUID.randomUUID()
        val updateRequest = TestDataFactory.createCreateRoleRequest("EXISTING_NAME")
        setupSecurityContext()
        every { roleService.updateRole(roleId, "EXISTING_NAME") } throws IllegalArgumentException("Role with name already exists")

        // When & Then
        mockMvc.perform(
            put("/roles/{id}", roleId)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(updateRequest)),
        )
            .andExpect(status().isBadRequest)

        verify { roleService.updateRole(roleId, "EXISTING_NAME") }
    }

    @Test
    fun `deleteRole should delete role and return success`() {
        // Given
        val roleId = UUID.randomUUID()
        setupSecurityContext()
        every { roleService.deleteRole(roleId) } just Runs

        // When & Then
        mockMvc.perform(delete("/roles/{id}", roleId))
            .andExpect(status().isOk)

        verify { roleService.deleteRole(roleId) }
    }

    @Test
    fun `deleteRole should return not found when role does not exist`() {
        // Given
        val roleId = UUID.randomUUID()
        setupSecurityContext()
        every { roleService.deleteRole(roleId) } throws IllegalArgumentException("Role not found")

        // When & Then
        mockMvc.perform(delete("/roles/{id}", roleId))
            .andExpect(status().isNotFound)

        verify { roleService.deleteRole(roleId) }
    }

    @Test
    fun `createRole should return bad request for invalid input`() {
        // Given
        val invalidRequest = CreateRoleRequest(name = "") // Empty name
        setupSecurityContext()

        // When & Then
        mockMvc.perform(
            post("/roles")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(invalidRequest)),
        )
            .andExpect(status().isBadRequest)

        verify(exactly = 0) { roleService.createRole(any()) }
    }

    @Test
    fun `updateRole should return bad request for invalid input`() {
        // Given
        val roleId = UUID.randomUUID()
        val invalidRequest = CreateRoleRequest(name = "") // Empty name
        setupSecurityContext()

        // When & Then
        mockMvc.perform(
            put("/roles/{id}", roleId)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(invalidRequest)),
        )
            .andExpect(status().isBadRequest)

        verify(exactly = 0) { roleService.updateRole(any(), any()) }
    }

    @Test
    fun `createRole should return forbidden for non-admin users`() {
        // Given
        val createRequest = TestDataFactory.createCreateRoleRequest("NEW_ROLE")
        setupSecurityContext()
        every { authorizationUtils.hasPermission(any(), "ADMIN") } returns false

        // When & Then
        mockMvc.perform(
            post("/roles")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(createRequest)),
        )
            .andExpect(status().isForbidden)

        verify(exactly = 0) { roleService.createRole(any()) }
    }

    @Test
    fun `deleteRole should return forbidden for non-admin users`() {
        // Given
        val roleId = UUID.randomUUID()
        setupSecurityContext()
        every { authorizationUtils.hasPermission(any(), "ADMIN") } returns false

        // When & Then
        mockMvc.perform(delete("/roles/{id}", roleId))
            .andExpect(status().isForbidden)

        verify(exactly = 0) { roleService.deleteRole(any()) }
    }
}
