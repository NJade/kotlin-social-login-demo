package com.njade.kotlinlogin.config.security.handler

import com.njade.kotlinlogin.common.getCookie
import com.njade.kotlinlogin.config.security.oauth2.HttpCookieOAuth2AuthorizationRequestRepository
import com.njade.kotlinlogin.config.security.oauth2.HttpCookieOAuth2AuthorizationRequestRepository.Companion.REDIRECT_URI_PARAM_COOKIE
import org.springframework.security.core.AuthenticationException
import org.springframework.security.web.authentication.AuthenticationFailureHandler
import org.springframework.stereotype.Component
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

@Component
class OAuth2AuthenticationFailureHandler(
    val httpCookieOAuth2AuthorizationRequestRepository: HttpCookieOAuth2AuthorizationRequestRepository
) : AuthenticationFailureHandler {
    override fun onAuthenticationFailure(
        request: HttpServletRequest,
        response: HttpServletResponse,
        exception: AuthenticationException?
    ) {
        val cookie = request.getCookie(REDIRECT_URI_PARAM_COOKIE)
        val redirectUri = if (cookie == null) "/" else cookie.value
        httpCookieOAuth2AuthorizationRequestRepository.removeAuthorizationRequest(request)
        response.sendRedirect(redirectUri)
    }
}
