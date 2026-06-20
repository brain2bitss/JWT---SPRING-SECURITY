package com.example.jwt.controller;

import com.example.jwt.dto.AuthRequest;
import com.example.jwt.dto.AuthResponse;
import com.example.jwt.model.User;
import com.example.jwt.repository.UserRepository;
import com.example.jwt.service.JwtService;

import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;

@RestController
@RequestMapping()
public class AuthController {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    public AuthController(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtService jwtService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody AuthRequest req) {
        if (req.getUsername() == null || req.getPassword() == null) {
            return ResponseEntity.badRequest().body("username and password required");
        }
        if (userRepository.findByUsername(req.getUsername()).isPresent()) {
            return ResponseEntity.status(409).body("username exists");
        }
        User u = new User();
        u.setUsername(req.getUsername());
        u.setPassword(passwordEncoder.encode(req.getPassword()));
        User saved = userRepository.save(u);
        return ResponseEntity.created(URI.create("/users/" + saved.getId())).build();
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody AuthRequest req) {
        if (req.getUsername() == null || req.getPassword() == null) {
            return ResponseEntity.badRequest().body("username and password required");
        }
        return userRepository.findByUsername(req.getUsername())
                .map(user -> {
                    if (!passwordEncoder.matches(req.getPassword(), user.getPassword())) {
                        return ResponseEntity.status(401).body("invalid credentials");
                    }
                    String token = jwtService.generateToken(user.getUsername());
                    return ResponseEntity.ok(new AuthResponse(token));
                })
                .orElseGet(() -> ResponseEntity.status(401).body("invalid credentials"));
    }

    @GetMapping("/home")
    public ResponseEntity<?> home() {
        return ResponseEntity.ok("Welcome to JWT");
    }
}
