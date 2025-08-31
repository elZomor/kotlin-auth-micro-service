package com.auth

import org.junit.jupiter.api.Test
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.test.context.TestPropertySource

@SpringBootTest
@TestPropertySource(
    properties = [
        "spring.datasource.url=jdbc:h2:mem:testdb",
        "spring.jpa.hibernate.ddl-auto=create-drop",
        "jwt.secret=test-secret-key-for-context-loading-test-that-is-very-long",
        "jwt.issuer=test",
        "spring.liquibase.enabled=false"
    ]
)
class AuthApplicationTests {
    @Test
    fun contextLoads() {
    }
}
