package com.njade.kotlinlogin.common

import javax.servlet.http.Cookie
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

fun HttpServletRequest.getCookie(name: String): Cookie? {
    val cookieList = this.cookies.filter { it.name == name }
    if (cookieList.isEmpty()) {
        return null
    }
    return cookieList[0]
}

fun HttpServletResponse.deleteCookie(cookie: Cookie?) {
    if (cookie == null) {
        return
    }
    cookie.value = ""
    cookie.path = "/"
    cookie.maxAge = 0
    this.addCookie(cookie)
}

fun HttpServletResponse.addCookie(name: String, value: String, maxAge: Int) {
    val cookie = Cookie(name, value)
    cookie.path = "/"
    cookie.isHttpOnly = true
    cookie.maxAge = maxAge
    this.addCookie(cookie)
}
