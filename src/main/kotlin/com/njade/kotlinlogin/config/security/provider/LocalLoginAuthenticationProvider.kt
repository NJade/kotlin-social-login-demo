package com.njade.kotlinlogin.config.security.provider

import com.njade.kotlinlogin.account.AccountPrincipal
import com.njade.kotlinlogin.account.AccountService
import com.njade.kotlinlogin.config.security.token.PostAuthorizationToken
import com.njade.kotlinlogin.config.security.token.PreAuthorizationToken
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.core.Authentication
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Component

@Component
class LocalLoginAuthenticationProvider(
    private val accountService: AccountService,
    private val passwordEncoder: PasswordEncoder
) : AuthenticationProvider {

    override fun authenticate(authentication: Authentication?): Authentication {
        if (authentication !is PreAuthorizationToken) {
            throw java.lang.RuntimeException() // TODO
        }
        val name = authentication.principal
        val account = accountService.loadUserByUsername(name as String?)
        val password = authentication.credentials
        if (!passwordEncoder.matches(password as CharSequence?, account.password))
            throw RuntimeException() // TODO
        return PostAuthorizationToken(account as AccountPrincipal)
    }

    override fun supports(authentication: Class<*>?): Boolean {
        return PreAuthorizationToken::class.java.isAssignableFrom(authentication!!)
    }
}
