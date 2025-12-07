package kr.ac.kumoh.s20250000.w25w15_security.model

import org.springframework.data.annotation.Id
import org.springframework.data.mongodb.core.mapping.Document

@Document(collection = "users")
data class User(
    @Id
    val id: String? = null,
    val username: String,
    val password: String,
)
