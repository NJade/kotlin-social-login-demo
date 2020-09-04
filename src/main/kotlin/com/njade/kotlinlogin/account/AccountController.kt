package com.njade.kotlinlogin.account

import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import java.net.URI

@RestController
@RequestMapping("/api/account")
class AccountController(
    val accountService: AccountService
) {

    @PostMapping("/signup")
    fun signUp(
        @RequestBody signUpRequestDto: AccountControllerDto.SignUpRequestDto
    ): ResponseEntity<AccountControllerDto.SignUpResponseDto> {
        val serviceRequestDto = signUpRequestDto.toServiceDto()
        val serviceResponseDto = accountService.signUp(serviceRequestDto)
        return ResponseEntity.created(URI("/")) // ToDo
            .body(AccountControllerDto.SignUpResponseDto.of(serviceResponseDto))
    }
}
