package com.njade.kotlinlogin.config.security.provider

import com.njade.kotlinlogin.account.AccountPrincipal
import com.njade.kotlinlogin.account.AccountService
import com.njade.kotlinlogin.config.security.jwt.JwtTokenProvider
import com.njade.kotlinlogin.config.security.token.JwtPreProcessingToken
import com.njade.kotlinlogin.config.security.token.PostAuthorizationToken
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.core.Authentication
import org.springframework.stereotype.Component

@Component
class JwtAuthenticationProvider(
    private val jwtTokenProvider: JwtTokenProvider,
    private val accountService: AccountService
) : AuthenticationProvider {

    override fun authenticate(authentication: Authentication?): Authentication {
        val token = authentication!!.principal as String
        val decodeJwt = jwtTokenProvider.decodeJwt(token)
        val accountId = decodeJwt.subject.toLong()
        val accountPrincipal = accountService.loadAccountById(accountId)
        return PostAuthorizationToken(accountPrincipal as AccountPrincipal)
    }

    override fun supports(authentication: Class<*>?): Boolean {
        return JwtPreProcessingToken::class.java.isAssignableFrom(authentication!!)
    }
}
