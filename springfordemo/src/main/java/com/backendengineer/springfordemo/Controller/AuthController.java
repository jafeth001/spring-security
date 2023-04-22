package com.backendengineer.springfordemo.Controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;
    @PostMapping("/register")
    public ResponseEntity<AuthenticateResponse> Register
            (@RequestBody Registerrequest request){
        return ResponseEntity.ok(authService.Register(request));
    }
    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticateResponse> Authenticate
            (@RequestBody Authenticaterequest request){
        return ResponseEntity.ok(authService.Authenticate(request));
    }
}
