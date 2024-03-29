package com.easy.iam.authorization.controller;

import com.easy.iam.authorization.model.TokenRequest;
import com.easy.iam.authorization.model.TokenResponse;
import com.easy.iam.authorization.service.AuthorizationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

@RestController
@RequestMapping("/auth/tokens")
public class AuthorizationController {

    @Autowired
    AuthorizationService authorizationService;

    @PostMapping()
    public TokenResponse generateTokens(@RequestBody @Valid TokenRequest tokenRequest, BindingResult bindingResult) throws InvalidKeySpecException, NoSuchAlgorithmException, IOException {
        TokenResponse tokenResponse = authorizationService.generateTokens(tokenRequest);
        return tokenResponse;
    }
}
