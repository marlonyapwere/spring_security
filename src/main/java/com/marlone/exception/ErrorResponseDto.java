package com.marlone.exception;

import lombok.AllArgsConstructor;
import lombok.Data;
import org.springframework.http.HttpStatus;

@Data
@AllArgsConstructor
public class ErrorResponseDto {
    private  String apiPath;

    private HttpStatus errorCode;

    private  String errorMessage;

    private String errorTime;
}