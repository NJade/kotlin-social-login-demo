package com.njade.kotlinlogin.config.security.property

import org.assertj.core.api.Assertions
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest

@SpringBootTest
internal class OAuth2PropertyTest(
    @Autowired val oAuth2Property: OAuth2Property
) {

    @Test
    fun `property test`() {
        Assertions.assertThat(oAuth2Property.clients["google"]?.clientId)
            .isEqualTo("test-google-client-id")
        Assertions.assertThat(oAuth2Property.clients["google"]?.clientSecret)
            .isEqualTo("test-google-client-secret")
    }
}
