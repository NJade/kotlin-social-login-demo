package com.njade.kotlinlogin.config.security.token

import com.njade.kotlinlogin.config.security.dto.LocalLoginDto
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken

class PreAuthorizationToken(principal: Any, credentials: Any) :
    UsernamePasswordAuthenticationToken(principal, credentials) {

    constructor(localLoginDto: LocalLoginDto) :
        this(localLoginDto.email, localLoginDto.password)
}
