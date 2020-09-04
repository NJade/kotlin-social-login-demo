package com.njade.kotlinlogin.account

import java.time.LocalDateTime

class AccountServiceDto {
    data class SignUpRequestDto(
        val email: String,
        val password: String,
        val name: String
    ) {

        fun toEntity() = Account(null, email, password, name, null, null, null, null)
    }

    data class SignUpResponseDto(
        val id: Long,
        val email: String,
        val name: String,
        val createdAt: LocalDateTime
    ) {

        companion object {

            fun of(account: Account) =
                SignUpResponseDto(
                    account.id!!,
                    account.email,
                    account.name,
                    account.createdAt!!
                )
        }
    }
}
