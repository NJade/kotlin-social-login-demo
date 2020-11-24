package com.njade.kotlinlogin.config.security.jwt

import com.auth0.jwt.JWT
import com.auth0.jwt.JWTCreator
import com.auth0.jwt.algorithms.Algorithm
import com.auth0.jwt.interfaces.DecodedJWT
import com.njade.kotlinlogin.account.AccountPrincipal
import com.njade.kotlinlogin.common.property.JwtProperty
import org.springframework.stereotype.Component
import java.util.Date

// TODO
@Component
class JwtTokenProvider(
    private val jwtProperty: JwtProperty
) {

    fun generateJwtToken(principal: AccountPrincipal, expiredTime: Long, tokenType: String): String {
        return generateTokenBuilder(principal, expiredTime)
            .withClaim("token_type", tokenType)
            .sign(getAlgorithm())
    }

    fun generateTokenBuilder(principal: AccountPrincipal, expiredTime: Long): JWTCreator.Builder {
        return JWT.create()
            .withIssuer(jwtProperty.issuer)
            .withSubject(principal.id.toString())
            .withExpiresAt(Date(Date().time + expiredTime * 1000))
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

    companion object {

        const val ACCESS_TOKEN_TIME = 60 * 3L
        const val ACCESS_TOKEN_TYPE = "access"

        const val REFRESH_TOKEN_TIME = 60 * 60 * 24 * 30L
        const val REFRESH_TOKEN_TYPE = "refresh"
        const val REFRESH_TOKEN_COOKIE_NAME = "_ret"
    }
}
