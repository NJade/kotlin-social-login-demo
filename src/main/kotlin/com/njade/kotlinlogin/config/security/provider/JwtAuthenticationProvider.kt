package com.njade.kotlinlogin.config.security.provider

import com.njade.kotlinlogin.account.AccountPrincipal
import com.njade.kotlinlogin.account.AccountService
import com.njade.kotlinlogin.config.security.jwt.JwtTokenProvider
import com.njade.kotlinlogin.config.security.jwt.JwtTokenProvider.Companion.ACCESS_TOKEN_TYPE
import com.njade.kotlinlogin.config.security.jwt.JwtTokenProvider.Companion.REFRESH_TOKEN_TYPE
import com.njade.kotlinlogin.config.security.token.JwtPreProcessingToken
import com.njade.kotlinlogin.config.security.token.PostAuthorizationToken
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.core.Authentication
import org.springframework.stereotype.Component
import java.util.Date

@Component
class JwtAuthenticationProvider(
    private val jwtTokenProvider: JwtTokenProvider,
    private val accountService: AccountService
) : AuthenticationProvider {

    override fun authenticate(authentication: Authentication): Authentication {
        val token = authentication.principal as String
        val decodeJwt = jwtTokenProvider.decodeJwt(token)
        val tokenType = decodeJwt.claims["token_type"] ?: throw RuntimeException() // ToDo
        if (tokenType.asString() != ACCESS_TOKEN_TYPE && tokenType.asString() != REFRESH_TOKEN_TYPE) {
            throw RuntimeException()
        }
        val accountId = decodeJwt.subject.toLong()
        val accountPrincipal = accountService.loadAccountById(accountId) as AccountPrincipal
        if (tokenType.asString() == REFRESH_TOKEN_TYPE) {
            val expiresAt = decodeJwt.expiresAt
            val refresh =
                expiresAt.before(Date(Date().time + JwtTokenProvider.REFRESH_TOKEN_TIME * 1000 / 2))
            return PostAuthorizationToken(accountPrincipal, refresh, token)
        }
        return PostAuthorizationToken(accountPrincipal)
    }

    override fun supports(authentication: Class<*>?): Boolean {
        return JwtPreProcessingToken::class.java.isAssignableFrom(authentication!!)
    }
}
