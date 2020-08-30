package com.njade.kotlinlogin.config.security.handler

import com.fasterxml.jackson.databind.ObjectMapper
import com.njade.kotlinlogin.account.AccountPrincipal
import com.njade.kotlinlogin.config.security.dto.TokenDto
import com.njade.kotlinlogin.config.security.jwt.JwtTokenProvider
import com.njade.kotlinlogin.config.security.token.PostAuthorizationToken
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.security.core.Authentication
import org.springframework.security.web.authentication.AuthenticationSuccessHandler
import org.springframework.stereotype.Component
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

@Component
class LocalLoginAuthenticationSuccessHandler(
    private val jwtTokenProvider: JwtTokenProvider,
    private val objectMapper: ObjectMapper
) : AuthenticationSuccessHandler {

    override fun onAuthenticationSuccess(
        request: HttpServletRequest?,
        response: HttpServletResponse?,
        authentication: Authentication?
    ) {
        val postAuthorizationToken = authentication as PostAuthorizationToken
        val principal = postAuthorizationToken.principal as AccountPrincipal
        val token = jwtTokenProvider.generateToken(principal, 180)
        processResponse(response, TokenDto(token))
    }

    private fun processResponse(response: HttpServletResponse?, tokenDto: TokenDto) {
        response!!.contentType = MediaType.APPLICATION_JSON_VALUE
        response.status = HttpStatus.OK.value()
        response.writer.write(objectMapper.writeValueAsString(tokenDto))
    }
}
