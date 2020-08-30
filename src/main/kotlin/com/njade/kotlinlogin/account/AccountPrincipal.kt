package com.njade.kotlinlogin.account

import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.oauth2.core.user.OAuth2User

class AccountPrincipal(
    val id: Long,
    private val email: String,
    private val password: String,
    private val authorities: MutableCollection<out GrantedAuthority>,
    private val attributes: MutableMap<String, Any>
) : OAuth2User, UserDetails {

    override fun isEnabled(): Boolean {
        return true
    }

    override fun getUsername(): String {
        return email
    }

    override fun isCredentialsNonExpired(): Boolean {
        return true
    }

    override fun getPassword(): String {
        return password
    }

    override fun isAccountNonExpired(): Boolean {
        return true
    }

    override fun isAccountNonLocked(): Boolean {
        return true
    }

    override fun getName(): String {
        return email
    }

    override fun getAttributes(): MutableMap<String, Any> {
        return attributes
    }

    override fun getAuthorities(): MutableCollection<out GrantedAuthority> {
        return authorities
    }

    companion object {

        fun of(account: Account): AccountPrincipal {
            return AccountPrincipal(
                account.id!!,
                account.email,
                account.password ?: "NONE",
                mutableListOf(SimpleGrantedAuthority("ROLE_" + account.role!!.name)),
                mutableMapOf()
            )
        }
    }
}
