package kr.ac.kumoh.s20250000.w25w15_security.controller

import jakarta.servlet.http.HttpServletResponse
import kr.ac.kumoh.s20250000.w25w15_security.service.UserService
import kr.ac.kumoh.s20250000.w25w15_security.util.JwtUtil
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseCookie
import org.springframework.http.ResponseEntity
import org.springframework.security.core.Authentication
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
        val accessToken = jwtUtil.generateAccessToken(username)

        val cookie = ResponseCookie.from("accessToken", accessToken)
            .httpOnly(true)
            .secure(false) // TODO: HTTPS를 사용하고 secure를 true로 변경할 것
            .path("/")
            .maxAge(Duration.ofMillis(20 * 1000L)) // 20초
            //.maxAge(Duration.ofMinutes(30)) // 30분
            .sameSite("Strict")
            .build()
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString())

        // Refresh Token도 사용하면 사용자 입장에서 더 편함
        val refreshToken = jwtUtil.generateRefreshToken(username)
        val refreshTokenCookie = ResponseCookie.from("refreshToken", refreshToken)
            .httpOnly(true)
            .secure(false) // TODO: HTTPS를 사용하고 secure를 true로 변경할 것
            .path("/")
            .maxAge(Duration.ofMillis(40 * 1000L)) // 40초
            //.maxAge(Duration.ofDays(15)) // 15일
            .sameSite("Strict")
            .build()
        response.addHeader(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString())

        return ResponseEntity.ok("회원 가입 성공")
    }

    @PostMapping("/login")
    fun login(
        @RequestParam username: String,
        @RequestParam password: String,
        response: HttpServletResponse,
    ): ResponseEntity<String> {
        if (userService.authenticate(username, password)) {
            val accessToken = jwtUtil.generateAccessToken(username)

            val cookie = ResponseCookie.from("accessToken", accessToken)
                .httpOnly(true)
                .secure(false) // TODO: HTTPS를 사용하고 secure를 true로 변경할 것
                .path("/")
                .maxAge(Duration.ofMillis(20 * 1000L)) // 20초
                //.maxAge(Duration.ofMinutes(30)) // 30분
                .sameSite("Strict")
                .build()
            response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString())

            // Refresh Token도 사용하면 사용자 입장에서 더 편함
            val refreshToken = jwtUtil.generateRefreshToken(username)
            val refreshTokenCookie = ResponseCookie.from("refreshToken", refreshToken)
                .httpOnly(true)
                .secure(false) // TODO: HTTPS를 사용하고 secure를 true로 변경할 것
                .path("/")
                .maxAge(Duration.ofMillis(40 * 1000L)) // 40초
                //.maxAge(Duration.ofDays(15)) // 15일
                .sameSite("Strict")
                .build()
            response.addHeader(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString())

            return ResponseEntity.ok("로그인 성공")
        } else {
            return ResponseEntity
                .status(HttpStatus.UNAUTHORIZED) // 401
                .body("로그인 실패")
        }
    }

    @GetMapping("/status")
    fun getUserStatus(authentication: Authentication): ResponseEntity<Map<String, String>> {
        // Authentication에 문제가 있다면 이 함수에 도달하기 전에
        // 이전의 JwtAuthenticationFilter 단계에서 에러 반환

        // SecurityContext에 저장된 username 사용
        val username = authentication.name

        return ResponseEntity
            .ok(mapOf("username" to username))
    }
}