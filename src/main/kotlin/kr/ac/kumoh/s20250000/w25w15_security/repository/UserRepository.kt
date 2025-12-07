package kr.ac.kumoh.s20250000.w25w15_security.repository

import kr.ac.kumoh.s20250000.w25w15_security.model.User
import org.springframework.data.mongodb.repository.MongoRepository

interface UserRepository : MongoRepository<User, String> {
    fun findByUsername(username: String): User?
}