package com.njade.kotlinlogin.config.security.token

import com.njade.kotlinlogin.account.AccountPrincipal
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.GrantedAuthority

class PostAuthorizationToken(
    principal: Any,
    credentials: Any,
    authorities: MutableCollection<out GrantedAuthority>,
    val refresh: Boolean = false,
    val oldToken: String? = null
) : UsernamePasswordAuthenticationToken(
    principal,
    credentials,
    authorities
) {

    constructor(account: AccountPrincipal) :
        this(account, account.password, account.authorities)

    constructor(account: AccountPrincipal, refresh: Boolean, oldToken: String) :
        this(account, oldToken, account.authorities, refresh, oldToken)
}
