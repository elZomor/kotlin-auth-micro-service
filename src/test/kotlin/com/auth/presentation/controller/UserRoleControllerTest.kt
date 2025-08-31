package com.auth.presentation.controller

import com.auth.common.TestDataFactory
import com.auth.domain.model.UserRole
import com.auth.domain.service.UserRoleService
import com.auth.infrastructure.security.AuthorizationUtils
import com.auth.infrastructure.security.Permissions
import com.auth.presentation.dto.AssignUserRoleRequest
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
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import org.springframework.test.web.servlet.setup.MockMvcBuilders
import java.util.UUID

class UserRoleControllerTest {
    private val userRoleService = mockk<UserRoleService>(relaxed = true)
    private val authorizationUtils = mockk<AuthorizationUtils>(relaxed = true)

    private lateinit var userRoleController: UserRoleController
    private lateinit var mockMvc: MockMvc
    private val objectMapper = ObjectMapper()

    @BeforeEach
    fun setup() {
        clearAllMocks()
        userRoleController = UserRoleController(userRoleService, authorizationUtils)
        mockMvc = MockMvcBuilders.standaloneSetup(userRoleController).build()
    }

    @Test
    fun `assignUserToRole should assign user to role successfully when user has permission`() {
        // Given
        val userId = UUID.randomUUID()
        val roleId = UUID.randomUUID()
        val assignRequest = TestDataFactory.createAssignUserRoleRequest(userId, roleId)
        val userRole = TestDataFactory.createUserRole(userId = userId, roleId = roleId)
        val authentication = mockk<Authentication>()
        val authorities = listOf(SimpleGrantedAuthority(Permissions.USER_ROLE_ASSIGN))

        every { authentication.name } returns "admin@example.com"
        every { authentication.authorities } returns authorities
        every { authorizationUtils.hasPermission(authentication, Permissions.USER_ROLE_ASSIGN) } returns true
        every { userRoleService.assignUserToRole(userId, roleId) } returns userRole

        // When & Then
        mockMvc.perform(
            post("/admin/user-roles/assign")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(assignRequest))
                .principal(authentication)
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.message").value("User assigned to role successfully"))
            .andExpect(jsonPath("$.userRole.userId").value(userId.toString()))
            .andExpect(jsonPath("$.userRole.roleId").value(roleId.toString()))

        verify { userRoleService.assignUserToRole(userId, roleId) }
        verify { authorizationUtils.hasPermission(authentication, Permissions.USER_ROLE_ASSIGN) }
    }

    @Test
    fun `assignUserToRole should return forbidden when user lacks permission`() {
        // Given
        val userId = UUID.randomUUID()
        val roleId = UUID.randomUUID()
        val assignRequest = TestDataFactory.createAssignUserRoleRequest(userId, roleId)
        val authentication = mockk<Authentication>()

        every { authentication.name } returns "user@example.com"
        every { authorizationUtils.hasPermission(authentication, Permissions.USER_ROLE_ASSIGN) } returns false

        // When & Then
        mockMvc.perform(
            post("/admin/user-roles/assign")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(assignRequest))
                .principal(authentication)
        )
            .andExpect(status().isForbidden)
            .andExpect(jsonPath("$.error").value("Insufficient permissions. Required: ${Permissions.USER_ROLE_ASSIGN}"))

        verify { authorizationUtils.hasPermission(authentication, Permissions.USER_ROLE_ASSIGN) }
        verify(exactly = 0) { userRoleService.assignUserToRole(any(), any()) }
    }

    @Test
    fun `assignUserToRole should return bad request when service throws exception`() {
        // Given
        val userId = UUID.randomUUID()
        val roleId = UUID.randomUUID()
        val assignRequest = TestDataFactory.createAssignUserRoleRequest(userId, roleId)
        val authentication = mockk<Authentication>()
        val authorities = listOf(SimpleGrantedAuthority(Permissions.USER_ROLE_ASSIGN))

        every { authentication.name } returns "admin@example.com"
        every { authentication.authorities } returns authorities
        every { authorizationUtils.hasPermission(authentication, Permissions.USER_ROLE_ASSIGN) } returns true
        every { userRoleService.assignUserToRole(userId, roleId) } throws IllegalArgumentException("User or role not found")

        // When & Then
        mockMvc.perform(
            post("/admin/user-roles/assign")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(assignRequest))
                .principal(authentication)
        )
            .andExpect(status().isBadRequest)
            .andExpect(jsonPath("$.error").value("Illegal User or role not found"))

        verify { userRoleService.assignUserToRole(userId, roleId) }
    }

    @Test
    fun `removeUserFromRole should remove user from role successfully when user has permission`() {
        // Given
        val userId = UUID.randomUUID()
        val roleId = UUID.randomUUID()
        val authentication = mockk<Authentication>()
        val authorities = listOf(SimpleGrantedAuthority(Permissions.USER_ROLE_REMOVE))

        every { authentication.name } returns "admin@example.com"
        every { authentication.authorities } returns authorities
        every { authorizationUtils.hasPermission(authentication, Permissions.USER_ROLE_REMOVE) } returns true
        every { userRoleService.removeUserFromRole(userId, roleId) } returns Unit

        // When & Then
        mockMvc.perform(
            delete("/admin/user-roles/remove")
                .param("userId", userId.toString())
                .param("roleId", roleId.toString())
                .principal(authentication)
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.message").value("User removed from role successfully"))

        verify { userRoleService.removeUserFromRole(userId, roleId) }
        verify { authorizationUtils.hasPermission(authentication, Permissions.USER_ROLE_REMOVE) }
    }

    @Test
    fun `removeUserFromRole should return forbidden when user lacks permission`() {
        // Given
        val userId = UUID.randomUUID()
        val roleId = UUID.randomUUID()
        val authentication = mockk<Authentication>()

        every { authentication.name } returns "user@example.com"
        every { authorizationUtils.hasPermission(authentication, Permissions.USER_ROLE_REMOVE) } returns false

        // When & Then
        mockMvc.perform(
            delete("/admin/user-roles/remove")
                .param("userId", userId.toString())
                .param("roleId", roleId.toString())
                .principal(authentication)
        )
            .andExpect(status().isForbidden)
            .andExpect(jsonPath("$.error").value("Insufficient permissions. Required: ${Permissions.USER_ROLE_REMOVE}"))

        verify { authorizationUtils.hasPermission(authentication, Permissions.USER_ROLE_REMOVE) }
        verify(exactly = 0) { userRoleService.removeUserFromRole(any(), any()) }
    }

    @Test
    fun `removeUserFromRole should return bad request when service throws exception`() {
        // Given
        val userId = UUID.randomUUID()
        val roleId = UUID.randomUUID()
        val authentication = mockk<Authentication>()
        val authorities = listOf(SimpleGrantedAuthority(Permissions.USER_ROLE_REMOVE))

        every { authentication.name } returns "admin@example.com"
        every { authentication.authorities } returns authorities
        every { authorizationUtils.hasPermission(authentication, Permissions.USER_ROLE_REMOVE) } returns true
        every { userRoleService.removeUserFromRole(userId, roleId) } throws IllegalArgumentException("User role assignment not found")

        // When & Then
        mockMvc.perform(
            delete("/admin/user-roles/remove")
                .param("userId", userId.toString())
                .param("roleId", roleId.toString())
                .principal(authentication)
        )
            .andExpect(status().isBadRequest)
            .andExpect(jsonPath("$.error").value("Illegal User role assignment not found"))

        verify { userRoleService.removeUserFromRole(userId, roleId) }
    }

    @Test
    fun `getUserRoles should return user roles when user has permission`() {
        // Given
        val userId = UUID.randomUUID()
        val userRoles = listOf(
            TestDataFactory.createUserRole(userId = userId, roleId = UUID.randomUUID()),
            TestDataFactory.createUserRole(userId = userId, roleId = UUID.randomUUID())
        )
        val authentication = mockk<Authentication>()
        val authorities = listOf(SimpleGrantedAuthority(Permissions.USER_ROLE_READ))

        every { authentication.name } returns "admin@example.com"
        every { authentication.authorities } returns authorities
        every { authorizationUtils.hasPermission(authentication, Permissions.USER_ROLE_READ) } returns true
        every { userRoleService.getUserRoles(userId) } returns userRoles

        // When & Then
        mockMvc.perform(
            get("/admin/user-roles/user/$userId")
                .principal(authentication)
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.userId").value(userId.toString()))
            .andExpect(jsonPath("$.roles").isArray)
            .andExpect(jsonPath("$.roles.length()").value(2))

        verify { userRoleService.getUserRoles(userId) }
        verify { authorizationUtils.hasPermission(authentication, Permissions.USER_ROLE_READ) }
    }

    @Test
    fun `getUserRoles should return forbidden when user lacks permission`() {
        // Given
        val userId = UUID.randomUUID()
        val authentication = mockk<Authentication>()

        every { authentication.name } returns "user@example.com"
        every { authorizationUtils.hasPermission(authentication, Permissions.USER_ROLE_READ) } returns false

        // When & Then
        mockMvc.perform(
            get("/admin/user-roles/user/$userId")
                .principal(authentication)
        )
            .andExpect(status().isForbidden)
            .andExpect(jsonPath("$.error").value("Insufficient permissions. Required: ${Permissions.USER_ROLE_READ}"))

        verify { authorizationUtils.hasPermission(authentication, Permissions.USER_ROLE_READ) }
        verify(exactly = 0) { userRoleService.getUserRoles(any()) }
    }

    @Test
    fun `getRoleUsers should return role users when user has permission`() {
        // Given
        val roleId = UUID.randomUUID()
        val roleUsers = listOf(
            TestDataFactory.createUserRole(userId = UUID.randomUUID(), roleId = roleId),
            TestDataFactory.createUserRole(userId = UUID.randomUUID(), roleId = roleId)
        )
        val authentication = mockk<Authentication>()
        val authorities = listOf(SimpleGrantedAuthority(Permissions.USER_ROLE_READ))

        every { authentication.name } returns "admin@example.com"
        every { authentication.authorities } returns authorities
        every { authorizationUtils.hasPermission(authentication, Permissions.USER_ROLE_READ) } returns true
        every { userRoleService.getRoleUsers(roleId) } returns roleUsers

        // When & Then
        mockMvc.perform(
            get("/admin/user-roles/role/$roleId")
                .principal(authentication)
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.roleId").value(roleId.toString()))
            .andExpect(jsonPath("$.users").isArray)
            .andExpect(jsonPath("$.users.length()").value(2))

        verify { userRoleService.getRoleUsers(roleId) }
        verify { authorizationUtils.hasPermission(authentication, Permissions.USER_ROLE_READ) }
    }

    @Test
    fun `getRoleUsers should return forbidden when user lacks permission`() {
        // Given
        val roleId = UUID.randomUUID()
        val authentication = mockk<Authentication>()

        every { authentication.name } returns "user@example.com"
        every { authorizationUtils.hasPermission(authentication, Permissions.USER_ROLE_READ) } returns false

        // When & Then
        mockMvc.perform(
            get("/admin/user-roles/role/$roleId")
                .principal(authentication)
        )
            .andExpect(status().isForbidden)
            .andExpect(jsonPath("$.error").value("Insufficient permissions. Required: ${Permissions.USER_ROLE_READ}"))

        verify { authorizationUtils.hasPermission(authentication, Permissions.USER_ROLE_READ) }
        verify(exactly = 0) { userRoleService.getRoleUsers(any()) }
    }

    @Test
    fun `assignUserToRole should return bad request for invalid input`() {
        // Given
        val invalidRequest = """{"userId": null, "roleId": null}"""
        val authentication = mockk<Authentication>()
        val authorities = listOf(SimpleGrantedAuthority(Permissions.USER_ROLE_ASSIGN))

        every { authentication.name } returns "admin@example.com"
        every { authentication.authorities } returns authorities
        every { authorizationUtils.hasPermission(authentication, Permissions.USER_ROLE_ASSIGN) } returns true

        // When & Then
        mockMvc.perform(
            post("/admin/user-roles/assign")
                .contentType(MediaType.APPLICATION_JSON)
                .content(invalidRequest)
                .principal(authentication)
        )
            .andExpect(status().isBadRequest)

        verify(exactly = 0) { userRoleService.assignUserToRole(any(), any()) }
    }
}