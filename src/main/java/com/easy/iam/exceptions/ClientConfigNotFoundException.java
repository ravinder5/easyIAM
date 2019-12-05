package com.easy.iam.exceptions;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(value = HttpStatus.NOT_FOUND)
public class ClientConfigNotFoundException extends RuntimeException {
    public ClientConfigNotFoundException() {
        super();
    }
    public ClientConfigNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }
    public ClientConfigNotFoundException(String message) {
        super(message);
    }
    public ClientConfigNotFoundException(Throwable cause) {
        super(cause);
    }
}
