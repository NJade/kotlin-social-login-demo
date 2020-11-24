package com.njade.kotlinlogin.account.oauth2

class GoogleOAuth2AccountInfo(
    attributes: MutableMap<String, Any>
) : OAuth2AccountInfo(attributes) {
    override fun getId(): String {
        return attributes["sub"] as String
    }

    override fun getName(): String {
        return attributes["name"] as String
    }

    override fun getEmail(): String {
        return attributes["email"] as String
    }
}
