package com.njade.kotlinlogin.config.security.handler

import com.fasterxml.jackson.databind.ObjectMapper
import com.njade.kotlinlogin.account.AccountPrincipal
import com.njade.kotlinlogin.common.deleteCookie
import com.njade.kotlinlogin.config.security.jwt.JwtTokenProvider
import com.njade.kotlinlogin.config.security.jwt.JwtTokenProvider.Companion.ACCESS_TOKEN_TIME
import com.njade.kotlinlogin.config.security.jwt.JwtTokenProvider.Companion.ACCESS_TOKEN_TYPE
import com.njade.kotlinlogin.config.security.jwt.JwtTokenProvider.Companion.REFRESH_TOKEN_COOKIE_NAME
import com.njade.kotlinlogin.config.security.jwt.JwtTokenProvider.Companion.REFRESH_TOKEN_TIME
import com.njade.kotlinlogin.config.security.jwt.JwtTokenProvider.Companion.REFRESH_TOKEN_TYPE
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
            jwtTokenProvider.generateJwtToken(principal, ACCESS_TOKEN_TIME, ACCESS_TOKEN_TYPE)
        var refreshToken: String? = null
        if (refresh) {
            val oldCookie = Cookie(REFRESH_TOKEN_COOKIE_NAME, oldToken)
            response.deleteCookie(oldCookie)
            refreshToken = jwtTokenProvider.generateJwtToken(principal, REFRESH_TOKEN_TIME, REFRESH_TOKEN_TYPE)
        }
        processResponse(response, accessToken, refreshToken)
    }
}
