package com.njade.kotlinlogin.config.security.jwt

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import com.auth0.jwt.interfaces.DecodedJWT
import com.njade.kotlinlogin.account.AccountPrincipal
import com.njade.kotlinlogin.config.security.property.JwtProperty
import org.springframework.stereotype.Component
import java.util.*

// TODO
@Component
class JwtTokenProvider(
    private val jwtProperty: JwtProperty
) {

    fun generateToken(principal: AccountPrincipal, expiredTime: Long): String {
        return JWT.create()
            .withIssuer(jwtProperty.issuer)
            .withSubject(principal.id.toString())
            .withExpiresAt(Date(Date().time + expiredTime * 1000))
            .sign(getAlgorithm())
    }

    fun decodeJwt(token: String): DecodedJWT {
        val verifier = JWT.require(getAlgorithm())
            .withIssuer(jwtProperty.issuer)
            .build()
        return verifier.verify(token)
    }

    fun getAlgorithm(): Algorithm? {
        return Algorithm.HMAC256(jwtProperty.secretKey)
    }
}
