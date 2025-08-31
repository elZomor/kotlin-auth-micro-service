package com.auth.infrastructure.security

import io.jsonwebtoken.Claims
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Service
import java.time.Instant
import java.util.concurrent.ConcurrentHashMap

@Service
class TokenBlacklistService {
    private val logger = LoggerFactory.getLogger(TokenBlacklistService::class.java)
    private val blacklistedTokens = ConcurrentHashMap<String, Long>()
    
    fun blacklistToken(token: String, jwtService: JwtService) {
        try {
            val claims = jwtService.parse(token)
            val expirationTime = claims.payload.expiration.time
            blacklistedTokens[token] = expirationTime
            logger.info("Token blacklisted successfully")
        } catch (e: Exception) {
            logger.error("Failed to blacklist token: ${e.message}")
        }
    }
    
    fun isTokenBlacklisted(token: String): Boolean {
        val expirationTime = blacklistedTokens[token] ?: return false
        
        // Remove expired tokens from memory
        if (expirationTime < System.currentTimeMillis()) {
            blacklistedTokens.remove(token)
            return false
        }
        
        return true
    }
    
    fun cleanupExpiredTokens() {
        val currentTime = System.currentTimeMillis()
        val expiredTokens = blacklistedTokens.entries
            .filter { it.value < currentTime }
            .map { it.key }
        
        expiredTokens.forEach { blacklistedTokens.remove(it) }
        
        if (expiredTokens.isNotEmpty()) {
            logger.info("Cleaned up ${expiredTokens.size} expired blacklisted tokens")
        }
    }
}