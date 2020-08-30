package com.njade.kotlinlogin.account

import com.fasterxml.jackson.databind.ObjectMapper
import com.njade.kotlinlogin.config.security.dto.LocalLoginDto
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
    @Autowired val mockMvc: MockMvc
) {

    @Test
    fun `integration test`() {
        val objectMapper = ObjectMapper()

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

        action2
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.token").exists())
    }
}
