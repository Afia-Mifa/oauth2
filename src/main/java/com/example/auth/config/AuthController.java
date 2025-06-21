package com.example.auth.config;

import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class AuthController {

    @GetMapping("fake-client")
    public ResponseEntity<?> callback(@RequestParam("code") String code, HttpServletResponse response) {
        return ResponseEntity.ok(code);
    }
}
