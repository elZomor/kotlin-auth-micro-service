package com.auth.presentation.dto

data class TokenResponse(
    val accessToken: String, 
    val refreshToken: String,
    val tokenType: String, 
    val expiresIn: Long
)