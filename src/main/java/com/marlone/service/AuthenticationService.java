package com.marlone.service;

import com.marlone.dao.request.SignUpRequest;
import com.marlone.dao.request.SigninRequest;
import com.marlone.dao.response.JwtAuthenticationResponse;

public interface AuthenticationService {
    JwtAuthenticationResponse signup(SignUpRequest request);

    JwtAuthenticationResponse signin(SigninRequest request);
}
