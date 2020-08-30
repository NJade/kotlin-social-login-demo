package com.njade.kotlinlogin.config.security.filter

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.njade.kotlinlogin.config.security.dto.LocalLoginDto
import com.njade.kotlinlogin.config.security.token.PreAuthorizationToken
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter
import org.springframework.security.web.authentication.AuthenticationFailureHandler
import org.springframework.security.web.authentication.AuthenticationSuccessHandler
import javax.servlet.FilterChain
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

class LocalLoginFilter(
    defaultUrl: String?,
    private val authenticationSuccessHandler: AuthenticationSuccessHandler,
    private val authenticationFailureHandler: AuthenticationFailureHandler
) : AbstractAuthenticationProcessingFilter(defaultUrl) {

    override fun attemptAuthentication(
        request: HttpServletRequest?,
        response: HttpServletResponse?
    ): Authentication {
        val loginDto = objectMapper.readValue(request!!.reader, LocalLoginDto::class.java)
        val preAuthorizationToken = PreAuthorizationToken(loginDto)
        return super.getAuthenticationManager().authenticate(preAuthorizationToken)
    }

    override fun unsuccessfulAuthentication(
        request: HttpServletRequest?,
        response: HttpServletResponse?,
        failed: AuthenticationException?
    ) {
        this.authenticationFailureHandler.onAuthenticationFailure(request, response, failed)
    }

    override fun successfulAuthentication(
        request: HttpServletRequest?,
        response: HttpServletResponse?,
        chain: FilterChain?,
        authResult: Authentication?
    ) {
        this.authenticationSuccessHandler.onAuthenticationSuccess(request, response, authResult)
    }

    companion object {

        val objectMapper = jacksonObjectMapper()
        val log: Logger = LoggerFactory.getLogger(LocalLoginFilter::class.java)
    }
}
