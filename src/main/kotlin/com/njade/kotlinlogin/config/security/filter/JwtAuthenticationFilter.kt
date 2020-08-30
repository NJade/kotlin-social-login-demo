package com.njade.kotlinlogin.config.security.filter

import com.njade.kotlinlogin.config.security.handler.JwtAuthenticationFailureHandler
import com.njade.kotlinlogin.config.security.token.JwtPreProcessingToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter
import org.springframework.security.web.util.matcher.RequestMatcher
import javax.servlet.FilterChain
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

class JwtAuthenticationFilter(
    requiresAuthenticationRequestMatcher: RequestMatcher?,
    private val jwtAuthenticationFailureHandler: JwtAuthenticationFailureHandler
) :
    AbstractAuthenticationProcessingFilter(requiresAuthenticationRequestMatcher) {

    override fun attemptAuthentication(
        request: HttpServletRequest?,
        response: HttpServletResponse?
    ): Authentication {
        val token = request!!.getHeader("Authorization")
        val jwtPreProcessingToken = JwtPreProcessingToken(headerExtract(token))
        return super.getAuthenticationManager().authenticate(jwtPreProcessingToken)
    }

    private fun headerExtract(header: String): String {
        if (header.isEmpty() || header.length < HEADER_PREFIX.length) {
            throw RuntimeException() // TODO
        }
        return header.substring(HEADER_PREFIX.length, header.length)
    }

    override fun successfulAuthentication(
        request: HttpServletRequest?,
        response: HttpServletResponse?,
        chain: FilterChain?,
        authResult: Authentication?
    ) {
        val context = SecurityContextHolder.createEmptyContext()
        context.authentication = authResult
        SecurityContextHolder.setContext(context)
        chain!!.doFilter(request, response)
    }

    override fun unsuccessfulAuthentication(
        request: HttpServletRequest?,
        response: HttpServletResponse?,
        failed: AuthenticationException?
    ) {
        SecurityContextHolder.clearContext()
        this.jwtAuthenticationFailureHandler.onAuthenticationFailure(request, response, failed)
    }

    companion object {

        const val HEADER_PREFIX = "Bearer "
    }
}
