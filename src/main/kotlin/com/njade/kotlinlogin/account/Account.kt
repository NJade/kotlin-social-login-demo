package com.njade.kotlinlogin.account

import au.com.console.kassava.kotlinEquals
import au.com.console.kassava.kotlinHashCode
import au.com.console.kassava.kotlinToString
import org.hibernate.annotations.CreationTimestamp
import org.hibernate.annotations.UpdateTimestamp
import java.time.LocalDateTime
import javax.persistence.Entity
import javax.persistence.EnumType
import javax.persistence.Enumerated
import javax.persistence.GeneratedValue
import javax.persistence.GenerationType
import javax.persistence.Id

@Entity
class Account(
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    var id: Long? = null,
    var email: String,
    var password: String? = null,
    var name: String,

    @Enumerated(EnumType.STRING)
    var role: AccountRole?,

    @CreationTimestamp
    var createdAt: LocalDateTime? = null,

    @UpdateTimestamp
    var updatedAt: LocalDateTime? = null,

    @Enumerated(EnumType.STRING)
    var provider: AuthProvider?
) {

    override fun equals(other: Any?) =
        kotlinEquals(other = other, properties = equalsAndHashCodeProperties)

    override fun hashCode() = kotlinHashCode(properties = equalsAndHashCodeProperties)

    override fun toString() = kotlinToString(properties = toStringProperties)

    companion object {

        private val equalsAndHashCodeProperties = arrayOf(Account::id)
        private val toStringProperties = arrayOf(
            Account::id,
            Account::email
        )
    }
}
