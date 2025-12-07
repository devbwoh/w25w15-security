package kr.ac.kumoh.s20250000.w25w15_security.controller

import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/api/data")
class DataController {

    private val data = listOf(
        "React",
        "TanStack Query",
        "React Router",
        "Tailwind CSS",
        "Axios",
    )

    @GetMapping()
    fun getAllData(): ResponseEntity<List<String>> {
        return ResponseEntity.ok(data)
    }
}