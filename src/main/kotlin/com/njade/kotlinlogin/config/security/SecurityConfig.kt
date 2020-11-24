package com.njade.kotlinlogin.config.security

import com.fasterxml.jackson.databind.ObjectMapper
import com.njade.kotlinlogin.account.oauth2.AccountOAuth2Service
import com.njade.kotlinlogin.common.property.OAuth2Property
import com.njade.kotlinlogin.config.security.filter.FilterSkipMatcher
import com.njade.kotlinlogin.config.security.filter.JwtAuthenticationFilter
import com.njade.kotlinlogin.config.security.filter.LocalLoginFilter
import com.njade.kotlinlogin.config.security.filter.RefreshTokenAuthenticationFilter
import com.njade.kotlinlogin.config.security.handler.JwtAuthenticationFailureHandler
import com.njade.kotlinlogin.config.security.handler.LocalLoginAuthenticationFailureHandler
import com.njade.kotlinlogin.config.security.handler.LocalLoginAuthenticationSuccessHandler
import com.njade.kotlinlogin.config.security.handler.OAuth2AuthenticationFailureHandler
import com.njade.kotlinlogin.config.security.handler.OAuth2AuthenticationSuccessHandler
import com.njade.kotlinlogin.config.security.handler.RefreshJwtAuthenticationFailureHandler
import com.njade.kotlinlogin.config.security.handler.RefreshJwtAuthenticationSuccessHandler
import com.njade.kotlinlogin.config.security.jwt.JwtTokenProvider.Companion.REFRESH_TOKEN_COOKIE_NAME
import com.njade.kotlinlogin.config.security.oauth2.HttpCookieOAuth2AuthorizationRequestRepository
import com.njade.kotlinlogin.config.security.provider.JwtAuthenticationProvider
import com.njade.kotlinlogin.config.security.provider.LocalLoginAuthenticationProvider
import org.springframework.boot.autoconfigure.security.servlet.PathRequest
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpMethod
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.builders.WebSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService
import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler
import org.springframework.security.web.util.matcher.AntPathRequestMatcher

@Configuration
@EnableWebSecurity
class SecurityConfig(
    val localLoginAuthenticationSuccessHandler: LocalLoginAuthenticationSuccessHandler,
    val localLoginAuthenticationFailureHandler: LocalLoginAuthenticationFailureHandler,
    val localLoginAuthenticationProvider: LocalLoginAuthenticationProvider,
    val jwtAuthenticationFailureHandler: JwtAuthenticationFailureHandler,
    val jwtAuthenticationProvider: JwtAuthenticationProvider,
    val refreshJwtAuthenticationSuccessHandler: RefreshJwtAuthenticationSuccessHandler,
    val refreshJwtAuthenticationFailureHandler: RefreshJwtAuthenticationFailureHandler,
    val oAuth2AuthenticationSuccessHandler: OAuth2AuthenticationSuccessHandler,
    val oAuth2AuthenticationFailureHandler: OAuth2AuthenticationFailureHandler,
    val cookieOAuth2AuthorizationRequestRepository: HttpCookieOAuth2AuthorizationRequestRepository,
    val accountOAuth2Service: AccountOAuth2Service,
    val objectMapper: ObjectMapper,
    val oAuth2Property: OAuth2Property
) : WebSecurityConfigurerAdapter() {

    fun localLoginFilter(): LocalLoginFilter {
        val localLoginFilter = LocalLoginFilter(
            requestMatcher("/login", HttpMethod.POST),
            objectMapper,
            localLoginAuthenticationSuccessHandler,
            localLoginAuthenticationFailureHandler
        )
        localLoginFilter.setAuthenticationManager(super.authenticationManagerBean())
        return localLoginFilter
    }

    fun jwtAuthenticationFilter(): JwtAuthenticationFilter {
        val filterSkipMatcher = FilterSkipMatcher(listOf("login", "/api/account/signup"), "/api/**")
        val jwtAuthenticationFilter =
            JwtAuthenticationFilter(filterSkipMatcher, jwtAuthenticationFailureHandler)
        jwtAuthenticationFilter.setAuthenticationManager(super.authenticationManagerBean())
        return jwtAuthenticationFilter
    }

    fun refreshTokenAuthenticationFilter(): RefreshTokenAuthenticationFilter {
        val refreshTokenAuthenticationFilter = RefreshTokenAuthenticationFilter(
            requestMatcher("/refresh_token", HttpMethod.POST),
            refreshJwtAuthenticationSuccessHandler,
            refreshJwtAuthenticationFailureHandler
        )
        refreshTokenAuthenticationFilter.setAuthenticationManager(super.authenticationManagerBean())
        return refreshTokenAuthenticationFilter
    }

    override fun configure(auth: AuthenticationManagerBuilder) {
        auth.authenticationProvider(this.localLoginAuthenticationProvider)
        auth.authenticationProvider(this.jwtAuthenticationProvider)
    }

    override fun configure(web: WebSecurity) {
        web
            .ignoring()
            .requestMatchers(PathRequest.toStaticResources().atCommonLocations())
    }

    override fun configure(http: HttpSecurity) {
        http
            .sessionManagement()
            .sessionCreationPolicy(SessionCreationPolicy.STATELESS)

        http
            .csrf()
            .disable()

        http
            .logout()
            .logoutSuccessHandler(customLogoutSuccessHandler())
            .deleteCookies(REFRESH_TOKEN_COOKIE_NAME)
            .logoutRequestMatcher(requestMatcher("/logout", HttpMethod.POST))

        http
            .addFilterBefore(
                localLoginFilter(),
                UsernamePasswordAuthenticationFilter::class.java
            )
            .addFilterBefore(
                jwtAuthenticationFilter(),
                UsernamePasswordAuthenticationFilter::class.java
            )
            .addFilterBefore(
                refreshTokenAuthenticationFilter(),
                UsernamePasswordAuthenticationFilter::class.java
            )

        http
            .oauth2Login()
            .clientRegistrationRepository(clientRegistrationRepository())
            .authorizedClientService(oAuth2AuthorizedClientService())
            .authorizationEndpoint()
            .authorizationRequestRepository(cookieOAuth2AuthorizationRequestRepository)

        http
            .oauth2Login()
            .userInfoEndpoint()
            .userService(accountOAuth2Service)

        http
            .oauth2Login()
            .successHandler(oAuth2AuthenticationSuccessHandler)
            .failureHandler(oAuth2AuthenticationFailureHandler)
    }

    @Bean
    fun clientRegistrationRepository(): ClientRegistrationRepository {
        val registrations = CLIENTS.mapNotNull { client -> getRegistration(client) }.toList()
        return InMemoryClientRegistrationRepository(registrations)
    }

    @Bean
    fun oAuth2AuthorizedClientService(): OAuth2AuthorizedClientService {
        return InMemoryOAuth2AuthorizedClientService(clientRegistrationRepository())
    }

    private fun customLogoutSuccessHandler(): LogoutSuccessHandler {
        return LogoutSuccessHandler { _, _, _ ->
            // Nothing
        }
    }

    fun requestMatcher(path: String, method: HttpMethod): AntPathRequestMatcher {
        return AntPathRequestMatcher(path, method.name)
    }

    fun getRegistration(client: String): ClientRegistration? {
        val oAuth2ClientProperty = oAuth2Property.clients[client] ?: return null
        return when (client) {
            "google" ->
                CommonOAuth2Provider.GOOGLE.getBuilder(client)
                    .clientId(oAuth2ClientProperty.clientId)
                    .clientSecret(oAuth2ClientProperty.clientSecret)
                    .scope("email", "profile")
                    .build()
            else -> null
        }
    }

    companion object {
        val CLIENTS = mutableListOf("google")
    }
}
