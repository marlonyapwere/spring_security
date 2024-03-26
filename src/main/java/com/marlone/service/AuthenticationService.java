package com.marlone.service;

import com.marlone.dao.request.SignUpRequest;
import com.marlone.dao.request.SigninRequest;
import com.marlone.dao.response.JwtAuthenticationResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

public interface AuthenticationService {
    JwtAuthenticationResponse signup(SignUpRequest request);

    JwtAuthenticationResponse signin(SigninRequest request);

    void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException;
}
