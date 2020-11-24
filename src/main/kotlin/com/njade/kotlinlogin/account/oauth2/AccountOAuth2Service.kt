package com.njade.kotlinlogin.account.oauth2

import com.fasterxml.jackson.databind.ObjectMapper
import com.njade.kotlinlogin.account.Account
import com.njade.kotlinlogin.account.AccountPrincipal
import com.njade.kotlinlogin.account.AccountRepository
import com.njade.kotlinlogin.account.AccountRole
import com.njade.kotlinlogin.account.AuthProvider
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest
import org.springframework.security.oauth2.core.user.OAuth2User
import org.springframework.stereotype.Service
import org.springframework.util.StringUtils

@Service
class AccountOAuth2Service(
    val accountRepository: AccountRepository,
    objectMapper: ObjectMapper
) : DefaultOAuth2UserService() {
    override fun loadUser(userRequest: OAuth2UserRequest): OAuth2User {
        val oAuth2User = super.loadUser(userRequest)
        val registrationId = userRequest.clientRegistration.registrationId.toUpperCase()
        val oAuth2AccountInfo =
            makeOAuth2AccountInfo(registrationId, oAuth2User.attributes) ?: throw RuntimeException() // ToDo
        val email = oAuth2AccountInfo.getEmail()
        if (StringUtils.isEmpty(email)) {
            throw RuntimeException() // TODO
        }
        val account = accountRepository.findByEmail(email) ?: return saveNewAccount(registrationId, oAuth2AccountInfo)
        if (!account.provider.toString().equals(registrationId)) {
            throw java.lang.RuntimeException() // ToDo
        }
        return updateAccount(account, oAuth2AccountInfo)
    }

    private fun updateAccount(account: Account, oAuth2AccountInfo: OAuth2AccountInfo): OAuth2User {
        account.name = oAuth2AccountInfo.getName()
        accountRepository.save(account)
        return AccountPrincipal.of(account)
    }

    private fun saveNewAccount(registrationId: String, oAuth2AccountInfo: OAuth2AccountInfo): OAuth2User {
        var account = Account(
            email = oAuth2AccountInfo.getEmail(), name = oAuth2AccountInfo.getName(),
            role = AccountRole.USER, provider = AuthProvider.valueOf(registrationId)
        )
        account = accountRepository.save(account)
        return AccountPrincipal.of(account)
    }

    private fun makeOAuth2AccountInfo(
        registrationId: String,
        attributes: MutableMap<String, Any>
    ): OAuth2AccountInfo? {
        return when (registrationId) {
            "GOOGLE" -> GoogleOAuth2AccountInfo(attributes)
            else -> null
        }
    }
}
