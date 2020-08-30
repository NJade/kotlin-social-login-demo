package com.njade.kotlinlogin.config.security.filter

import org.springframework.security.web.util.matcher.AntPathRequestMatcher
import org.springframework.security.web.util.matcher.OrRequestMatcher
import org.springframework.security.web.util.matcher.RequestMatcher
import javax.servlet.http.HttpServletRequest

class FilterSkipMatcher(
    private val skipMatcher: OrRequestMatcher,
    private val processingMatcher: RequestMatcher
) : RequestMatcher {

    constructor(pathToSkip: List<String>, processingPath: String) :
        this(
            OrRequestMatcher(pathToSkip.map { p -> AntPathRequestMatcher(p) }),
            AntPathRequestMatcher(processingPath)
        )

    override fun matches(request: HttpServletRequest?): Boolean {
        return !skipMatcher.matches(request) && processingMatcher.matches(request)
    }
}
