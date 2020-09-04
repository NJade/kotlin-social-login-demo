package com.njade.kotlinlogin.account

import java.time.LocalDateTime

class AccountControllerDto {

    data class SignUpRequestDto(
        val email: String? = null,
        val password: String? = null,
        val name: String? = null
    ) {

        fun toServiceDto(): AccountServiceDto.SignUpRequestDto =
            AccountServiceDto.SignUpRequestDto(email!!, password!!, name!!)
    }

    data class SignUpResponseDto(
        val id: Long,
        val email: String,
        val name: String,
        val createdAt: LocalDateTime
    ) {

        companion object {

            fun of(dto: AccountServiceDto.SignUpResponseDto): SignUpResponseDto =
                SignUpResponseDto(dto.id, dto.email, dto.name, dto.createdAt)
        }
    }
}
