package com.njade.kotlinlogin.common.property

import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.context.annotation.Configuration

@Configuration
@ConfigurationProperties(prefix = "jwt")
class JwtProperty {

    var issuer: String = ""
    var secretKey: String = ""
}
