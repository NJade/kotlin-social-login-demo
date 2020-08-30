package com.njade.kotlinlogin.config.security

import com.njade.kotlinlogin.config.security.filter.FilterSkipMatcher
import com.njade.kotlinlogin.config.security.filter.JwtAuthenticationFilter
import com.njade.kotlinlogin.config.security.filter.LocalLoginFilter
import com.njade.kotlinlogin.config.security.handler.JwtAuthenticationFailureHandler
import com.njade.kotlinlogin.config.security.handler.LocalLoginAuthenticationFailureHandler
import com.njade.kotlinlogin.config.security.handler.LocalLoginAuthenticationSuccessHandler
import com.njade.kotlinlogin.config.security.provider.JwtAuthenticationProvider
import com.njade.kotlinlogin.config.security.provider.LocalLoginAuthenticationProvider
import org.springframework.boot.autoconfigure.security.servlet.PathRequest
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.builders.WebSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter

@Configuration
@EnableWebSecurity
class SecurityConfig(
    val localLoginAuthenticationSuccessHandler: LocalLoginAuthenticationSuccessHandler,
    val localLoginAuthenticationFailureHandler: LocalLoginAuthenticationFailureHandler,
    val localLoginAuthenticationProvider: LocalLoginAuthenticationProvider,
    val jwtAuthenticationFailureHandler: JwtAuthenticationFailureHandler,
    val jwtAuthenticationProvider: JwtAuthenticationProvider
) : WebSecurityConfigurerAdapter() {

    fun localLoginFilter(): LocalLoginFilter {
        val localLoginFilter = LocalLoginFilter(
            "/login",
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
            .addFilterBefore(localLoginFilter(), UsernamePasswordAuthenticationFilter::class.java)
            .addFilterBefore(
                jwtAuthenticationFilter(),
                UsernamePasswordAuthenticationFilter::class.java
            )
    }
}
