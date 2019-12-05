package com.easy.iam.exceptions;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(value = HttpStatus.BAD_REQUEST)
public class AccountNotFoundException extends RuntimeException {
    public AccountNotFoundException() {
        super();
    }
    public AccountNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }
    public AccountNotFoundException(String message) {
        super(message);
    }
    public AccountNotFoundException(Throwable cause) {
        super(cause);
    }
}
