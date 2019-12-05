package com.easy.iam.exceptions;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(value = HttpStatus.UNAUTHORIZED)
public class GrantTypeNotAllowedException extends RuntimeException {
    public GrantTypeNotAllowedException() {
        super();
    }
    public GrantTypeNotAllowedException(String message, Throwable cause) {
        super(message, cause);
    }
    public GrantTypeNotAllowedException(String message) {
        super(message);
    }
    public GrantTypeNotAllowedException(Throwable cause) {
        super(cause);
    }
}
