package com.njade.kotlinlogin.account.oauth2

abstract class OAuth2AccountInfo(
    val attributes: MutableMap<String, Any>
) {
    abstract fun getId(): String
    abstract fun getName(): String
    abstract fun getEmail(): String
}
