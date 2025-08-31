package com.auth.infrastructure.security

import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jws
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.security.Keys
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Component
import java.time.Instant
import java.util.Date
import java.util.UUID
import javax.crypto.SecretKey

@Component
class JwtService(
    @Value("\${jwt.secret}") secret: String,
    @Value("\${jwt.issuer}") private val issuer: String,
) {
    private val key: SecretKey = Keys.hmacShaKeyFor(secret.toByteArray())

    fun generate(
        subject: String,
        authorities: Collection<String>,
        ttlSeconds: Long,
    ): String {
        val now = Instant.now()
        return Jwts.builder()
            .id(UUID.randomUUID().toString())
            .subject(subject)
            .issuer(issuer)
            .issuedAt(Date.from(now))
            .expiration(Date.from(now.plusSeconds(ttlSeconds)))
            .claim("authorities", authorities)
            .signWith(key)
            .compact()
    }

    fun parse(token: String): Jws<Claims> =
        Jwts.parser()
            .verifyWith(key)
            .build()
            .parseSignedClaims(token)

    fun generateRefreshToken(
        subject: String,
        ttlSeconds: Long = 7 * 24 * 3600,
    ): String {
        val now = Instant.now()
        return Jwts.builder()
            .id(UUID.randomUUID().toString())
            .subject(subject)
            .issuer(issuer)
            .issuedAt(Date.from(now))
            .expiration(Date.from(now.plusSeconds(ttlSeconds)))
            .claim("type", "refresh")
            .signWith(key)
            .compact()
    }

    fun generateAccessTokenFromRefreshToken(
        refreshToken: String,
        authorities: Collection<String>,
        ttlSeconds: Long = 3600,
    ): String {
        val claims = parse(refreshToken)
        val subject = claims.payload.subject
        val tokenType = claims.payload["type"] as? String

        if (tokenType != "refresh") {
            throw IllegalArgumentException("Invalid refresh token type")
        }

        return generate(subject, authorities, ttlSeconds)
    }

    fun isRefreshToken(token: String): Boolean {
        return try {
            val claims = parse(token)
            val tokenType = claims.payload["type"] as? String
            tokenType == "refresh"
        } catch (e: Exception) {
            false
        }
    }
}
