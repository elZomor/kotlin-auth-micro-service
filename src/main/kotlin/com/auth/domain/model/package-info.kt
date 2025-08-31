/**
 * Data models for the authentication system
 * 
 * This package contains:
 * - Core entity models that map to database tables
 * - Enhanced models with relationships for complex queries
 * - DTOs for API requests and responses
 * 
 * Database Schema:
 * - users: User accounts with email, username, password
 * - roles: Role definitions
 * - permissions: Permission definitions
 * - user_roles: Many-to-many relationship between users and roles
 * - role_permissions: Many-to-many relationship between roles and permissions
 */
package com.auth.domain.model