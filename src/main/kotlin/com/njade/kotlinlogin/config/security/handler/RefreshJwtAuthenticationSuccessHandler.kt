package com.njade.kotlinlogin.config.security.handler

import com.fasterxml.jackson.databind.ObjectMapper
import com.njade.kotlinlogin.account.AccountPrincipal
import com.njade.kotlinlogin.config.security.jwt.JwtTokenProvider
import com.njade.kotlinlogin.config.security.jwt.JwtTokenProvider.Companion.ACCESS_TOKEN_TIME
import com.njade.kotlinlogin.config.security.jwt.JwtTokenProvider.Companion.REFRESH_TOKEN_COOKIE_NAME
import com.njade.kotlinlogin.config.security.jwt.JwtTokenProvider.Companion.REFRESH_TOKEN_TIME
import com.njade.kotlinlogin.config.security.token.PostAuthorizationToken
import org.springframework.security.core.Authentication
import org.springframework.stereotype.Component
import javax.servlet.http.Cookie
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

@Component
class RefreshJwtAuthenticationSuccessHandler(
    private val jwtTokenProvider: JwtTokenProvider,
    objectMapper: ObjectMapper
) : BaseAuthenticationSuccessHandler(objectMapper) {

    override fun onAuthenticationSuccess(
        request: HttpServletRequest,
        response: HttpServletResponse,
        authentication: Authentication
    ) {
        val postAuthorizationToken = authentication as PostAuthorizationToken
        val principal = postAuthorizationToken.principal as AccountPrincipal

        val oldToken = postAuthorizationToken.oldToken
        val refresh = postAuthorizationToken.refresh
        val accessToken =
            jwtTokenProvider.generateAccessToken(principal, ACCESS_TOKEN_TIME)
        var refreshToken: String? = null
        if (refresh) {
            val oldCookie = Cookie(REFRESH_TOKEN_COOKIE_NAME, oldToken)
            oldCookie.maxAge = 0
            response.addCookie(oldCookie)
            refreshToken = jwtTokenProvider.generateRefreshToken(principal, REFRESH_TOKEN_TIME)
        }
        processResponse(response, accessToken, refreshToken)
    }
}
