package kr.ac.kumoh.s20250000.w25w15_security.filter

import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import kr.ac.kumoh.s20250000.w25w15_security.service.UserService
import kr.ac.kumoh.s20250000.w25w15_security.util.JwtUtil
import org.springframework.http.HttpHeaders
import org.springframework.http.ResponseCookie
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource
import org.springframework.util.AntPathMatcher
import org.springframework.web.filter.OncePerRequestFilter
import java.time.Duration

class JwtAuthenticationFilter(
    private val jwtUtil: JwtUtil,
    private val userService: UserService,
) : OncePerRequestFilter() {

    private val pathMatcher = AntPathMatcher()
    private val excludePath = listOf("" +
            "/api/auth/register",
            "/api/auth/login",
        )

    // Access Token과 Refresh Token이 없는 상태에서 login 시도할 때
    // AuthController의 login() 함수로 건너뜀 (filter 거치지 않음)
    // 나머지는 Filter를 거쳐서 Access Token 및 Refresh Token으로 권한 검사
    override fun shouldNotFilter(request: HttpServletRequest): Boolean {
        val requestURI = request.requestURI
        println(requestURI)

        val exclude = excludePath.any {
            pathMatcher.match(it, requestURI)
        }

        return exclude
    }

    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain
    ) {
        val accessToken = request.cookies
            ?.find { it.name == "accessToken" }
            ?.value

        //----------------------------------------------
        // Access Token 유효함
        //----------------------------------------------
        if (accessToken != null && jwtUtil.validateToken(accessToken)) {
            val username = jwtUtil.extractUsername(accessToken)
            println("doFilterInternal(): Valid Access Token")
            authenticateAndProceed(request, accessToken)
            filterChain.doFilter(request, response)
            return
        }

        println("doFilterInternal(): Invalid Access Token")

        //----------------------------------------------
        // Refresh Token 없음
        //----------------------------------------------
        val refreshToken = request.cookies
            ?.find { it.name == "refreshToken" }
            ?.value

        if (refreshToken == null) {
            println("doFilterInternal(): No Refresh Token")
            sendUnauthorizedError(response, "Refresh Token 없음")
            return
        }

        //----------------------------------------------
        // Refresh Token 유효하지 않음
        //----------------------------------------------
        if (!jwtUtil.validateToken(refreshToken)) {
            println("doFilterInternal(): Invalid Refresh Token")
            sendUnauthorizedError(response, "Refresh Token 유효하지 않음")
            return
        }

        //----------------------------------------------
        // Refresh Token 유효하므로, Access Token 갱신
        //----------------------------------------------
        println("doFilterInternal(): Valid Refresh Token, Update Access Token")
        try {
            val username = jwtUtil.extractUsername(refreshToken)
            val newAccessToken = jwtUtil.generateAccessToken(username)

            val newAccessTokenCookie = ResponseCookie.from("accessToken", newAccessToken)
                .httpOnly(true)
                .secure(false) // TODO: HTTPS를 사용하고 true로 변경
                .path("/")
                .maxAge(Duration.ofSeconds(20)) // 20초
                //.maxAge(Duration.ofMinutes(30)) // 30분
                .sameSite("Strict")
                .build()

            response.addHeader(HttpHeaders.SET_COOKIE, newAccessTokenCookie.toString())

            // 갱신된 Access Token으로 인증
            authenticateAndProceed(request, newAccessToken)
            filterChain.doFilter(request, response)
        } catch (e: Exception) {
            println("doFilterInternal(): Refresh Token Error: ${e.message}")
            sendUnauthorizedError(response, "토큰 갱신 에러")
        }
    }

    // 인증하고 Filter Chain의 다음 filter로 진행
    private fun authenticateAndProceed(request: HttpServletRequest, token: String) {
        val username = jwtUtil.extractUsername(token)
        val authentication = UsernamePasswordAuthenticationToken(
            username,
            null,
            emptyList()
        )
        authentication.details = WebAuthenticationDetailsSource()
            .buildDetails(request)
        // Spring SecurityContextHolder에 인증 정보 저장
        SecurityContextHolder.getContext().authentication = authentication
    }

    // Filter Chain 진행 종료
    private fun sendUnauthorizedError(response: HttpServletResponse, message: String) {
        response.status = HttpServletResponse.SC_UNAUTHORIZED // 401
        response.contentType = "application/json;charset=UTF-8"
        response.writer.write("{\"error\": \"Unauthorized\", \"message\": \"$message\"}")
        response.writer.flush()
    }
}