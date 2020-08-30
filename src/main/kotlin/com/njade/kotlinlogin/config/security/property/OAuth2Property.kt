package com.njade.kotlinlogin.config.security.property

import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.context.annotation.Configuration

@Configuration
@ConfigurationProperties(prefix = "oauth2")
class OAuth2Property {

    var clients: Map<String, Oauth2ClientProperty> = HashMap()

    class Oauth2ClientProperty {
        var clientId: String? = null
        var clientSecret: String? = null
    }
}
