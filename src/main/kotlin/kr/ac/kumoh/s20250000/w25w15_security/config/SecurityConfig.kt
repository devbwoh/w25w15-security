package kr.ac.kumoh.s20250000.w25w15_security.config

import kr.ac.kumoh.s20250000.w25w15_security.filter.JwtAuthenticationFilter
import kr.ac.kumoh.s20250000.w25w15_security.service.UserService
import kr.ac.kumoh.s20250000.w25w15_security.util.JwtUtil
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.CorsConfigurationSource
import org.springframework.web.cors.UrlBasedCorsConfigurationSource

@Configuration
class SecurityConfig(
    private val jwtUtil: JwtUtil,
    private val userService: UserService,
) {
    @Bean
    fun corsConfigurationSource(): CorsConfigurationSource {
        val configuration = CorsConfiguration()
        configuration.apply {
            allowedOrigins = listOf("http://localhost:5173") // 허용할 도메인
            allowedMethods = listOf("GET", "POST", "PUT", "DELETE", "OPTIONS") // 허용할 HTTP 메서드
            allowedHeaders = listOf("*") // 허용할 헤더. 필요에 따라 제한
            allowCredentials = true // 자격 증명(쿠키 등)을 허용할지 여부
        }
        val source = UrlBasedCorsConfigurationSource()
        source.registerCorsConfiguration("/**", configuration) // 모든 경로에 적용
        return source
    }

    @Bean
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
        return http
            .csrf { it.disable() }
            .cors { it.configurationSource(corsConfigurationSource()) } // CORS 설정 적용
            .authorizeHttpRequests { auth ->
                auth
                    .requestMatchers("/api/auth/**").permitAll() // 로그인, 회원가입 경로는 허용
                    .anyRequest().authenticated() // 나머지는 인증 필요
                    //.requestMatchers("/swagger-ui/**").permitAll()
                    //.requestMatchers("/api/data/**").authenticated()
                    //.anyRequest().permitAll()
            }
            .sessionManagement {
                it.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            }
            .addFilterBefore(
                JwtAuthenticationFilter(jwtUtil, userService),
                UsernamePasswordAuthenticationFilter::class.java // 기존 인증 필터보다 앞에 위치
            )
            .build()
    }
}