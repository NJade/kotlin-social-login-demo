package com.njade.kotlinlogin.config.security.handler

import com.fasterxml.jackson.databind.ObjectMapper
import com.njade.kotlinlogin.account.AccountPrincipal
import com.njade.kotlinlogin.common.deleteCookie
import com.njade.kotlinlogin.common.getCookie
import com.njade.kotlinlogin.config.security.jwt.JwtTokenProvider
import com.njade.kotlinlogin.config.security.jwt.JwtTokenProvider.Companion.ACCESS_TOKEN_TIME
import com.njade.kotlinlogin.config.security.jwt.JwtTokenProvider.Companion.ACCESS_TOKEN_TYPE
import com.njade.kotlinlogin.config.security.jwt.JwtTokenProvider.Companion.REFRESH_TOKEN_TIME
import com.njade.kotlinlogin.config.security.jwt.JwtTokenProvider.Companion.REFRESH_TOKEN_TYPE
import com.njade.kotlinlogin.config.security.oauth2.HttpCookieOAuth2AuthorizationRequestRepository
import org.springframework.security.core.Authentication
import org.springframework.stereotype.Component
import java.net.URI
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

@Component
class OAuth2AuthenticationSuccessHandler(
    val objectMapper: ObjectMapper,
    val tokenProvider: JwtTokenProvider
) : BaseAuthenticationSuccessHandler(objectMapper) {

    override fun onAuthenticationSuccess(
        request: HttpServletRequest,
        response: HttpServletResponse,
        authentication: Authentication
    ) {
        val cookie = request.getCookie(HttpCookieOAuth2AuthorizationRequestRepository.REDIRECT_URI_PARAM_COOKIE)
        response.deleteCookie(cookie)
        if (cookie != null && !isAuthorizedRedirectUri(cookie.value)) {
            throw RuntimeException() // TODO
        }
        val redirectUri = if (cookie == null) "/" else cookie.value

        val accountPrincipal = authentication.principal as AccountPrincipal
        val accessToken = tokenProvider.generateJwtToken(accountPrincipal, ACCESS_TOKEN_TIME, ACCESS_TOKEN_TYPE)
        val refreshToken = tokenProvider.generateJwtToken(accountPrincipal, REFRESH_TOKEN_TIME, REFRESH_TOKEN_TYPE)
        processResponse(response, accessToken, refreshToken)
        response.sendRedirect(redirectUri)
    }

    private fun isAuthorizedRedirectUri(uri: String): Boolean {
        val redirectUri = URI.create(uri)
        return AUTHORIZED_REDIRECT_URIS
            .stream()
            .anyMatch { authorizedRedirectUri ->
                // Only validate host and port. Let the clients use different paths if they want to
                val authorizedURI = URI.create(authorizedRedirectUri)
                if (authorizedURI.host.equals(redirectUri.host, ignoreCase = true) &&
                    authorizedURI.port == redirectUri.port
                ) {
                    return@anyMatch true
                }
                false
            }
    }

    companion object {
        val AUTHORIZED_REDIRECT_URIS = mutableListOf<String>("localhost:8080") // TODO
    }
}
