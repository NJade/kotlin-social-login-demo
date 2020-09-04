package com.njade.kotlinlogin.common

import javax.servlet.http.HttpServletRequest

fun HttpServletRequest.getCookies(name: String) = this.cookies.filter { it.name == name }
