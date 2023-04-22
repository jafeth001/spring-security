package com.backendengineer.springfordemo.Controller;

import com.backendengineer.springfordemo.Config.JwtService;
import com.backendengineer.springfordemo.Entity.Role;
import com.backendengineer.springfordemo.Entity.User;
import com.backendengineer.springfordemo.Repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    public AuthenticateResponse Register(Registerrequest request) {
      var user = User.builder()
              .firstname(request.getFirstname())
              .lastname(request.getLastname())
              .email(request.getEmail())
              .password(passwordEncoder.encode(request.getPassword()))
              .role(Role.USER)
              .build();
      userRepository.save(user);
      var jwttoken = jwtService.generatetoken(user);
      return AuthenticateResponse.builder()
              .token(jwttoken)
              .build();
    }
    public AuthenticateResponse Authenticate(Authenticaterequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );
        var user = userRepository.findByEmail(request.getEmail())
                .orElseThrow();
        var jwttoken = jwtService.generatetoken(user);
        return AuthenticateResponse.builder()
                .token(jwttoken)
                .build();


    }
}
