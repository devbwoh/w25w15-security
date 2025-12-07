package kr.ac.kumoh.s20250000.w25w15_security.filter

import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import kr.ac.kumoh.s20250000.w25w15_security.service.UserService
import kr.ac.kumoh.s20250000.w25w15_security.util.JwtUtil
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource
import org.springframework.web.filter.OncePerRequestFilter

class JwtAuthenticationFilter(
    private val jwtUtil: JwtUtil,
    private val userService: UserService,
) : OncePerRequestFilter() {

    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain
    ) {
        val accessToken = request.cookies
            ?.find { it.name == "accessToken" }
            ?.value

        if (accessToken != null && jwtUtil.validateToken(accessToken)) {
            val username = jwtUtil.extractUsername(accessToken)
            val authentication = UsernamePasswordAuthenticationToken(
                username,
                null,
                emptyList()
            )
            authentication.details = WebAuthenticationDetailsSource()
                .buildDetails(request)
            SecurityContextHolder.getContext().authentication = authentication
        }

        filterChain.doFilter(request, response)
    }
}