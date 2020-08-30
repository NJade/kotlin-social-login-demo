package com.njade.kotlinlogin.account

import org.springframework.data.jpa.repository.JpaRepository

interface AccountRepository : JpaRepository<Account, Long> {

    fun findByEmail(email: String): Account?
    fun findAccountById(id: Long): Account?
}
