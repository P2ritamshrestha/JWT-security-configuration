package com.jwt.security.stha.service.Impl;
import com.jwt.security.stha.DTO.JwtAuthenticationResponse;
import com.jwt.security.stha.DTO.RefreshTokenRequest;
import com.jwt.security.stha.DTO.SignInRequest;
import com.jwt.security.stha.DTO.SignUpRequest;
import com.jwt.security.stha.model.Role;
import com.jwt.security.stha.model.User;
import com.jwt.security.stha.repository.UserRepository;
import com.jwt.security.stha.service.AuthenticationService;
import com.jwt.security.stha.service.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashMap;

@RequiredArgsConstructor
@Service
public class AuthenticationServiceImpl implements AuthenticationService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;

    public User signUp(SignUpRequest signUpRequest) {
        User user = new User();
        user.setFullName(signUpRequest.getFullName());
        user.setUsername(signUpRequest.getUsername());
        user.setPassword(passwordEncoder.encode(signUpRequest.getPassword()));
        user.setRole(Role.ADMIN);
        userRepository.save(user);
        return user;
    }

    public JwtAuthenticationResponse signIn(SignInRequest signInRequest) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(signInRequest.getUsername(), signInRequest.getPassword()));

        var user = userRepository.findByUsername(signInRequest.getUsername()).orElseThrow(() -> new UsernameNotFoundException("User not found"));
        var jwt = jwtService.generateToken(user);
        var refreshToken = jwtService.generateRefereshToken(new HashMap<>(),user);

        JwtAuthenticationResponse jwtAuthenticationResponse= new JwtAuthenticationResponse();
        jwtAuthenticationResponse.setToken(jwt);
        jwtAuthenticationResponse.setRefreshToken((String) refreshToken);
        return jwtAuthenticationResponse;
    }

    public JwtAuthenticationResponse refreshToken(RefreshTokenRequest refreshTokenRequest) {
        String username= jwtService.extractUserName(refreshTokenRequest.getToken());
        User user = userRepository.findByUsername(username).orElseThrow(() -> new UsernameNotFoundException("User not found"));

        if(jwtService.isValidToken(refreshTokenRequest.getToken(),user)){
            var jwt = jwtService.generateToken(user);


            JwtAuthenticationResponse jwtAuthenticationResponse= new JwtAuthenticationResponse();
            jwtAuthenticationResponse.setToken(jwt);
            jwtAuthenticationResponse.setRefreshToken(refreshTokenRequest.getToken());
            return jwtAuthenticationResponse;
        }
        return null;
    }

}
