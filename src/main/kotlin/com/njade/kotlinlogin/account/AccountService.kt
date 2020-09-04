package com.njade.kotlinlogin.account

import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Service

@Service
class AccountService(
    val accountRepository: AccountRepository,
    val passwordEncoder: PasswordEncoder
) : UserDetailsService {

    override fun loadUserByUsername(email: String?): UserDetails {
        if (email == null) {
            throw RuntimeException() // ToDo
        }
        val account: Account = accountRepository.findByEmail(email) ?: throw RuntimeException()

        return AccountPrincipal.of(account)
    }

    fun loadAccountById(id: Long): UserDetails {
        val account: Account = accountRepository.findAccountById(id) ?: throw RuntimeException()
        return AccountPrincipal.of(account)
    }

    fun signUp(signUpRequestDto: AccountServiceDto.SignUpRequestDto): AccountServiceDto.SignUpResponseDto {
        val email = signUpRequestDto.email
        val existedAccount: Account? = accountRepository.findByEmail(email)
        if (existedAccount != null) {
            throw RuntimeException() // ToDo
        }
        val account = signUpRequestDto.toEntity()
        account.password = passwordEncoder.encode(account.password)
        account.provider = AuthProvider.LOCAL
        account.role = AccountRole.USER
        val savedAccount = accountRepository.save(account)
        return AccountServiceDto.SignUpResponseDto.of(savedAccount)
    }
}
