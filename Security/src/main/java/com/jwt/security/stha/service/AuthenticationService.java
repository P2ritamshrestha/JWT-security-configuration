package com.jwt.security.stha.service;
import com.jwt.security.stha.DTO.JwtAuthenticationResponse;
import com.jwt.security.stha.DTO.RefreshTokenRequest;
import com.jwt.security.stha.DTO.SignInRequest;
import com.jwt.security.stha.DTO.SignUpRequest;
import com.jwt.security.stha.model.User;

public interface AuthenticationService {
    User signUp(SignUpRequest signUpRequest);
    JwtAuthenticationResponse signIn(SignInRequest signInRequest);
    JwtAuthenticationResponse refreshToken(RefreshTokenRequest refreshTokenRequest);
}
