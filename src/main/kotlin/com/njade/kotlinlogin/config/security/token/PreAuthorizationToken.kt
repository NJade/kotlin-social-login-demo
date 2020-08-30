package com.njade.kotlinlogin.config.security.token

import com.njade.kotlinlogin.config.security.dto.LocalLoginDto
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken

class PreAuthorizationToken(principal: String, credentials: String) :
    UsernamePasswordAuthenticationToken(principal, credentials) {

    constructor(localLoginDto: LocalLoginDto) :
        this(localLoginDto.email, localLoginDto.password)
}
