package com.njade.kotlinlogin.config.security.token

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken

class JwtPreProcessingToken(principal: Any, credentials: Any) :
    UsernamePasswordAuthenticationToken(principal, credentials) {

    constructor(token: String) :
        this(token, token.length)
}
