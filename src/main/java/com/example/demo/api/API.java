package com.example.demo.api;

import com.example.demo.entity.User;
import com.example.demo.entity.UserRepo;
import com.example.demo.service.JWTService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RestController
public class API {
    private final AuthenticationManager authenticationManager;
    private final JWTService jwtService;
    private final UserDetailsService userDetailsService;
    private final UserRepo user;

    public API(AuthenticationManager authenticationManager, JWTService jwtService, UserDetailsService userDetailsService, UserRepo user) {
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
        this.userDetailsService = userDetailsService;
        this.user = user;
    }

    @GetMapping("/userall")
    @PreAuthorize("hasAuthority('customer')")
    public List<User> all() {
        return user.findAll();
    }

    @PostMapping(path = "/auth")
    public ResponseEntity<String> authenticate(@RequestBody Map<String, String> authRequest) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(authRequest.get("username"), authRequest.get("password"))
        );
        return ResponseEntity.ok(jwtService.createToken(userDetailsService.loadUserByUsername(authRequest.get("username"))));
    }
}
