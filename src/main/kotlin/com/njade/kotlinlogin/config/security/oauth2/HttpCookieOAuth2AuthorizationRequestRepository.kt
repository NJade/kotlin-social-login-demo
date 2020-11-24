package com.njade.kotlinlogin.config.security.oauth2

import com.njade.kotlinlogin.common.addCookie
import com.njade.kotlinlogin.common.deleteCookie
import com.njade.kotlinlogin.common.getCookie
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest
import org.springframework.stereotype.Component
import org.springframework.util.SerializationUtils
import org.springframework.util.StringUtils
import java.util.Base64
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

@Component
class HttpCookieOAuth2AuthorizationRequestRepository : AuthorizationRequestRepository<OAuth2AuthorizationRequest> {
    override fun loadAuthorizationRequest(request: HttpServletRequest): OAuth2AuthorizationRequest {
        val cookie = request.getCookie(OAUTH2_AUTHORIZATION_REQUEST_COOKIE) ?: throw RuntimeException() // TODO
        val decodeUrl = Base64.getUrlDecoder().decode(cookie.value)
        return SerializationUtils.deserialize(decodeUrl) as OAuth2AuthorizationRequest
    }

    override fun saveAuthorizationRequest(
        authorizationRequest: OAuth2AuthorizationRequest?,
        request: HttpServletRequest,
        response: HttpServletResponse
    ) {
        if (authorizationRequest == null) {
            val oauth2RequestCookie = request.getCookie(OAUTH2_AUTHORIZATION_REQUEST_COOKIE)
            val redirectUriCookie = request.getCookie(REDIRECT_URI_PARAM_COOKIE)
            response.deleteCookie(oauth2RequestCookie)
            response.deleteCookie(redirectUriCookie)
            return
        }
        val encodedAuthorizationRequest =
            Base64.getUrlEncoder().encodeToString(SerializationUtils.serialize(authorizationRequest))
        response.addCookie(OAUTH2_AUTHORIZATION_REQUEST_COOKIE, encodedAuthorizationRequest, COOKIE_EXPIRE_SECONDS)
        val redirectUrl = request.getParameter(REDIRECT_URI_PARAM)
        if (!StringUtils.isEmpty(redirectUrl)) {
            response.addCookie(REDIRECT_URI_PARAM_COOKIE, redirectUrl, COOKIE_EXPIRE_SECONDS)
        }
    }

    override fun removeAuthorizationRequest(request: HttpServletRequest): OAuth2AuthorizationRequest {
        return this.loadAuthorizationRequest(request)
    }

    companion object {
        const val OAUTH2_AUTHORIZATION_REQUEST_COOKIE = "oauth2_auth_request"
        const val REDIRECT_URI_PARAM = "redirect_url"
        const val REDIRECT_URI_PARAM_COOKIE = "redirect_url"
        const val COOKIE_EXPIRE_SECONDS = 180
    }
}
