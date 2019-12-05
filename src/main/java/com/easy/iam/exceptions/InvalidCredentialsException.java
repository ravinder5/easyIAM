package com.easy.iam.exceptions;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(value = HttpStatus.BAD_REQUEST)
public class InvalidCredentialsException extends RuntimeException {
    public InvalidCredentialsException() {
        super();
    }
    public InvalidCredentialsException(String message, Throwable cause) {
        super(message, cause);
    }
    public InvalidCredentialsException(String message) {
        super(message);
    }
    public InvalidCredentialsException(Throwable cause) {
        super(cause);
    }
}
