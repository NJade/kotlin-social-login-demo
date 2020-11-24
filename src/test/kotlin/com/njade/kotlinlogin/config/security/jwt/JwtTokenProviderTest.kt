package com.njade.kotlinlogin.config.security.jwt

import com.auth0.jwt.exceptions.TokenExpiredException
import com.njade.kotlinlogin.account.AccountPrincipal
import com.njade.kotlinlogin.config.security.jwt.JwtTokenProvider.Companion.ACCESS_TOKEN_TYPE
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest

@SpringBootTest
internal class JwtTokenProviderTest(
    @Autowired val jwtTokenProvider: JwtTokenProvider
) {

    @Test
    fun `jwt token test`() {
        val accountPrincipal = AccountPrincipal(1, "a", "a", mutableListOf(), mutableMapOf())
        val generateToken = jwtTokenProvider.generateJwtToken(accountPrincipal, 1, ACCESS_TOKEN_TYPE)
        val decodeJwt = jwtTokenProvider.decodeJwt(generateToken)
        assertThat(decodeJwt.issuer).isEqualTo("issuer")
        assertThat(decodeJwt.subject.toLong()).isEqualTo(1)
        Thread.sleep(2000)
        val exception = Assertions.assertThrows(TokenExpiredException::class.java) {
            jwtTokenProvider.decodeJwt(generateToken)
        }
        assertThat(exception).isNotNull()
    }
}
