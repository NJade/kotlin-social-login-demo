package com.njade.kotlinlogin.account

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import com.njade.kotlinlogin.config.security.dto.LocalLoginDto
import com.njade.kotlinlogin.config.security.dto.TokenDto
import org.assertj.core.api.Assertions.*
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.http.MediaType
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.*

@SpringBootTest
@AutoConfigureMockMvc
internal class AccountControllerTest(
    @Autowired val mockMvc: MockMvc,
    @Autowired val objectMapper: ObjectMapper
) {

    @Test
    fun `integration test`() {
        val email = "a"
        val password = "a"
        val name = "a"
        val signUpDto = AccountControllerDto.SignUpRequestDto(email, password, name)

        val action1 = mockMvc.perform(
            post("/api/account/signup")
                .contentType(MediaType.APPLICATION_JSON_VALUE)
                .content(objectMapper.writeValueAsString(signUpDto))
        )

        action1
            .andExpect(status().isCreated)
            .andExpect(jsonPath("$.email").value(email))

        val loginDto = LocalLoginDto(email, password)
        val action2 = mockMvc.perform(
            post("/login")
                .contentType(MediaType.APPLICATION_JSON_VALUE)
                .content(objectMapper.writeValueAsString(loginDto))
        )

        val ret = action2
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.token").exists())
            .andExpect(cookie().exists("_ret"))
            .andReturn()

        val cookies = ret.response.cookies
        val cookie = cookies.filter {
            it.name == "_ret"
        }[0]
        val token = objectMapper.readValue<TokenDto>(ret.response.contentAsString)
        Thread.sleep(1000)
        val ret2 = mockMvc.perform(
            post("/refresh_token")
                .cookie(cookie)
        )
            .andExpect(jsonPath("$.token").exists())
            .andReturn()

        val token2 = objectMapper.readValue<TokenDto>(ret2.response.contentAsString)
        assertThat(token2.token).isNotEqualTo(token.token)
    }
}
