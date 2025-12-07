package kr.ac.kumoh.s20250000.w25w15_security.controller

import jakarta.servlet.http.Cookie
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import kr.ac.kumoh.s20250000.w25w15_security.service.UserService
import kr.ac.kumoh.s20250000.w25w15_security.util.JwtUtil
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.*
import java.time.Duration

@RestController
@RequestMapping("/api/auth")
//@CrossOrigin(origins = ["http://localhost:5173"])
class AuthController(
    private val jwtUtil: JwtUtil,
    private val userService: UserService,
) {
    @PostMapping("/register")
    fun register(
        @RequestParam username: String,
        @RequestParam password: String,
        response: HttpServletResponse,
    ): ResponseEntity<String> {
        val user = userService.saveUser(username, password)
        val token = jwtUtil.generateToken(username)

        val cookie = Cookie("accessToken", token).apply {
            isHttpOnly = true

            // TODO: HTTPS를 사용하고 secure를 true로 변경할 것
            secure = false

            path = "/"
            maxAge = (Duration.ofMillis(20 * 1000L).toSeconds()).toInt() // 20초
            //maxAge = (Duration.ofMillis(60 * 60 * 1000L).toSeconds()).toInt() // 1시간
        }
        response.addCookie(cookie)
        return ResponseEntity.ok("회원 가입 성공")
    }

    @PostMapping("/login")
    fun login(
        @RequestParam username: String,
        @RequestParam password: String,
        response: HttpServletResponse,
    ): ResponseEntity<String> {
        if (userService.authenticate(username, password)) {
            val token = jwtUtil.generateToken(username)

            val cookie = Cookie("accessToken", token).apply {
                isHttpOnly = true

                // TODO: HTTPS를 사용하고 secure를 true로 변경할 것
                secure = false

                path = "/"
                maxAge = (Duration.ofMillis(20 * 1000L).toSeconds()).toInt() // 20초
                //maxAge = (Duration.ofMillis(60 * 60 * 1000L).toSeconds()).toInt() // 1시간
            }
            response.addCookie(cookie)
            return ResponseEntity.ok("로그인 성공")
        } else {
            return ResponseEntity
                .status(HttpStatus.UNAUTHORIZED) // 401
                .body("로그인 실패")
        }
    }

    @GetMapping("/status")
    fun getUserStatus(request: HttpServletRequest): ResponseEntity<Map<String, String>> {
        val accessToken = request.cookies?.find { it.name == "accessToken" }?.value
        if (accessToken == null || !jwtUtil.validateToken(accessToken)) {
            return ResponseEntity
                .status(HttpStatus.UNAUTHORIZED)
                .body(mapOf("error" to "Unauthorized"))
        }

        val username = try {
            jwtUtil.extractUsername(accessToken)
        } catch (e: Exception) {
            // 토큰은 있지만 유효하지 않음
            return ResponseEntity
                .status(HttpStatus.UNAUTHORIZED)
                .body(mapOf("error" to "Token invalid"))
        }

        return ResponseEntity
            .ok(mapOf("username" to username))
    }

}