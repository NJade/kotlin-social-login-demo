package com.njade.kotlinlogin.config.security.handler

import com.fasterxml.jackson.databind.ObjectMapper
import com.njade.kotlinlogin.config.security.dto.TokenDto
import com.njade.kotlinlogin.config.security.jwt.JwtTokenProvider
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.security.web.authentication.AuthenticationSuccessHandler
import javax.servlet.http.Cookie
import javax.servlet.http.HttpServletResponse

abstract class BaseAuthenticationSuccessHandler(
    private val objectMapper: ObjectMapper
) : AuthenticationSuccessHandler {

    protected fun processResponse(
        response: HttpServletResponse,
        accessToken: String,
        refreshToken: String?
    ) {
        response.contentType = MediaType.APPLICATION_JSON_VALUE
        response.status = HttpStatus.OK.value()
        setAccessToken(response, accessToken)
        if (refreshToken != null) {
            setRefreshToken(response, refreshToken)
        }
    }

    private fun setAccessToken(response: HttpServletResponse, accessToken: String) {
        response.writer.write(objectMapper.writeValueAsString(TokenDto(accessToken)))
    }

    private fun setRefreshToken(response: HttpServletResponse, refreshToken: String) {
        val cookie = Cookie(JwtTokenProvider.REFRESH_TOKEN_COOKIE_NAME, refreshToken)
        cookie.maxAge = JwtTokenProvider.REFRESH_TOKEN_TIME.toInt()
        cookie.isHttpOnly = true
//        cookie.secure = true
        response.addCookie(cookie)
    }
}
