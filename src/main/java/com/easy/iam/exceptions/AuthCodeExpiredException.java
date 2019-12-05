package com.easy.iam.exceptions;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(value = HttpStatus.UNAUTHORIZED)
public class AuthCodeExpiredException extends RuntimeException {
    public AuthCodeExpiredException() {
        super();
    }
    public AuthCodeExpiredException(String message, Throwable cause) {
        super(message, cause);
    }
    public AuthCodeExpiredException(String message) {
        super(message);
    }
    public AuthCodeExpiredException(Throwable cause) {
        super(cause);
    }
}
