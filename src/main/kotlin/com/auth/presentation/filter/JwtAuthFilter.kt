package com.auth.presentation.filter

import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter

@Component
class JwtAuthFilter(
    private val jwt: JwtService,
    private val uds: AppUserDetailsService,
    private val tokenBlacklistService: TokenBlacklistService
) : OncePerRequestFilter() {
    override fun doFilterInternal(request: HttpServletRequest, response: HttpServletResponse, chain: FilterChain) {
        val header = request.getHeader("Authorization")
        if (header?.startsWith("Bearer ") == true) {
            val token = header.substring(7)
            try {
                // Check if token is blacklisted
                if (tokenBlacklistService.isTokenBlacklisted(token)) {
                    chain.doFilter(request, response)
                    return
                }
                
                val claims = jwt.parse(token).payload
                val email = claims.subject
                val user = uds.loadUserByUsername(email)
                val auth = UsernamePasswordAuthenticationToken(user, null, user.authorities)
                SecurityContextHolder.getContext().authentication = auth
            } catch (_: Exception) { /* ignore invalid token */ }
        }
        chain.doFilter(request, response)
    }
}