package com.njade.kotlinlogin.config.security.filter

import com.fasterxml.jackson.databind.ObjectMapper
import com.njade.kotlinlogin.config.security.dto.LocalLoginDto
import com.njade.kotlinlogin.config.security.token.PreAuthorizationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter
import org.springframework.security.web.authentication.AuthenticationFailureHandler
import org.springframework.security.web.authentication.AuthenticationSuccessHandler
import org.springframework.security.web.util.matcher.RequestMatcher
import javax.servlet.FilterChain
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

class LocalLoginFilter(
    requestMatcher: RequestMatcher,
    private val objectMapper: ObjectMapper,
    private val authenticationSuccessHandler: AuthenticationSuccessHandler,
    private val authenticationFailureHandler: AuthenticationFailureHandler
) : AbstractAuthenticationProcessingFilter(requestMatcher) {

    override fun attemptAuthentication(
        request: HttpServletRequest,
        response: HttpServletResponse
    ): Authentication {
        val loginDto = objectMapper.readValue(request.reader, LocalLoginDto::class.java)
        val preAuthorizationToken = PreAuthorizationToken(loginDto)
        return super.getAuthenticationManager().authenticate(preAuthorizationToken)
    }

    override fun unsuccessfulAuthentication(
        request: HttpServletRequest,
        response: HttpServletResponse,
        failed: AuthenticationException
    ) {
        this.authenticationFailureHandler.onAuthenticationFailure(request, response, failed)
    }

    override fun successfulAuthentication(
        request: HttpServletRequest,
        response: HttpServletResponse,
        chain: FilterChain,
        authResult: Authentication
    ) {
        this.authenticationSuccessHandler.onAuthenticationSuccess(request, response, authResult)
    }
}
