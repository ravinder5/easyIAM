package com.easy.iam.authorization.service;

import com.easy.iam.authorization.model.TokenRequest;
import com.easy.iam.authorization.model.TokenResponse;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public interface AuthorizationService {
    public TokenResponse generateTokens(TokenRequest tokenRequest) throws InvalidKeySpecException, NoSuchAlgorithmException, IOException;
}
