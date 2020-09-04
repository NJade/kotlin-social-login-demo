package com.njade.kotlinlogin.config.security.filter

import com.njade.kotlinlogin.common.getCookies
import com.njade.kotlinlogin.config.security.jwt.JwtTokenProvider.Companion.REFRESH_TOKEN_COOKIE_NAME
import com.njade.kotlinlogin.config.security.token.JwtPreProcessingToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter
import org.springframework.security.web.authentication.AuthenticationFailureHandler
import org.springframework.security.web.authentication.AuthenticationSuccessHandler
import org.springframework.security.web.util.matcher.RequestMatcher
import javax.servlet.FilterChain
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

class RefreshTokenAuthenticationFilter(
    requestMatcher: RequestMatcher,
    private val authenticationSuccessHandler: AuthenticationSuccessHandler,
    private val authenticationFailureHandler: AuthenticationFailureHandler
) : AbstractAuthenticationProcessingFilter(requestMatcher) {

    override fun attemptAuthentication(
        request: HttpServletRequest,
        response: HttpServletResponse
    ): Authentication {
        val tokenCookie = request.getCookies(REFRESH_TOKEN_COOKIE_NAME)
        if (tokenCookie.isEmpty()) {
            throw RuntimeException() // ToDo
        }
        val refreshToken = tokenCookie[0]
        val jwtPreProcessingToken = JwtPreProcessingToken(refreshToken.value)
        return super.getAuthenticationManager().authenticate(jwtPreProcessingToken)
    }

    override fun successfulAuthentication(
        request: HttpServletRequest,
        response: HttpServletResponse,
        chain: FilterChain,
        authResult: Authentication
    ) {
        this.authenticationSuccessHandler.onAuthenticationSuccess(request, response, authResult)
    }

    override fun unsuccessfulAuthentication(
        request: HttpServletRequest,
        response: HttpServletResponse,
        failed: AuthenticationException
    ) {
        this.authenticationFailureHandler.onAuthenticationFailure(request, response, failed)
    }
}
