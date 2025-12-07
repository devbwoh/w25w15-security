package kr.ac.kumoh.s20250000.w25w15_security.util

import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import io.jsonwebtoken.security.Keys
import jakarta.annotation.PostConstruct
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Component
import java.security.Key
import java.util.*

@Component
class JwtUtil {
    companion object {
        //private const val EXPIRATION_TIME = 60 * 60 * 1000 // 1 시간
        private const val EXPIRATION_TIME = 20 * 1000 // 20 초
    }

    //@Value($$"${jwt.secret}")
    @Value("\${jwt.secret}")
    private lateinit var base64EncodedSecretKey: String
    private lateinit var key: Key

    @PostConstruct
    fun init() {
        // base64EncodedSecretKey가 주입된 후, key 초기화
        val decodedKey = Base64.getDecoder().decode(base64EncodedSecretKey)
        key = Keys.hmacShaKeyFor(decodedKey)
    }

    fun generateToken(username: String): String {
        return Jwts.builder()
            .setSubject(username)
            .setIssuedAt(Date())
            .setExpiration(Date(System.currentTimeMillis() + EXPIRATION_TIME))
            .signWith(key, SignatureAlgorithm.HS256)
            .compact()
    }

    fun validateToken(token: String): Boolean {
        return try {
            val claims = Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .body
            claims.expiration.after(Date())
        } catch (e: Exception) {
            false
        }
    }

    fun extractUsername(token: String): String {
        return Jwts.parserBuilder()
            .setSigningKey(key)
            .build()
            .parseClaimsJws(token)
            .body.subject
    }
}