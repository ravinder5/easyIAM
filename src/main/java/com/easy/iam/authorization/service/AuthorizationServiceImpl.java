package com.easy.iam.authorization.service;

import com.easy.iam.authorization.model.TokenRequest;
import com.easy.iam.authorization.model.TokenResponse;
import com.easy.iam.encryption.CryptoService;
import com.easy.iam.exceptions.AuthCodeExpiredException;
import com.easy.iam.exceptions.ClientConfigNotFoundException;
import com.easy.iam.exceptions.GrantTypeNotAllowedException;
import com.easy.iam.model.AuthCode;
import com.easy.iam.model.ClientConfig;
import com.easy.iam.model.TokenById;
import com.easy.iam.repository.AuthCodeRepository;
import com.easy.iam.repository.ClientConfigRepository;
import com.easy.iam.repository.TokenRepository;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.apache.commons.lang3.StringUtils;
import org.joda.time.DateTime;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

@Service
public class AuthorizationServiceImpl implements AuthorizationService {

    @Autowired
    AuthCodeRepository authCodeRepository;

    @Autowired
    ClientConfigRepository clientConfigRepository;

    @Autowired
    TokenRepository tokenRepository;

    @Autowired
    CryptoService cryptoService;

    @Override
    public TokenResponse generateTokens(TokenRequest tokenRequest) throws InvalidKeySpecException, NoSuchAlgorithmException, IOException {
        Optional<ClientConfig> clientConfig = clientConfigRepository.findById(tokenRequest.getClient_id());
        if (clientConfig.isEmpty()) {
            throw new ClientConfigNotFoundException("Client config not found");
        }
        if (StringUtils.equals(tokenRequest.getGrant_type(), "authorization_code")) {
            return getTokenResponseUsingAuthCodeFlow(tokenRequest, clientConfig.get());
        } else {
            throw new GrantTypeNotAllowedException("Grant Type not allowed");
        }
    }

    private TokenResponse getTokenResponseUsingAuthCodeFlow(TokenRequest tokenRequest, ClientConfig clientConfig) throws InvalidKeySpecException, NoSuchAlgorithmException, IOException {
        if (!clientConfig.getGrant_types().contains(tokenRequest.getGrant_type())) {
            throw new GrantTypeNotAllowedException("Grant Type not allowed");
        }
        Optional<AuthCode> authCode = authCodeRepository.findById(tokenRequest.getCode());
        if (authCode.isPresent()) {
            String tokenId = UUID.randomUUID().toString();
            String jwt = generateJWTToken(authCode.get(), tokenId, clientConfig);
            TokenById tokenById = new TokenById();
            tokenById.setToken_id(tokenId);
            tokenById.setClient_id(authCode.get().getClient_id());
            tokenById.setScope(authCode.get().getScope());
            tokenById.setUser_id(authCode.get().getUser_id());
            tokenById.setUser_name(authCode.get().getUser_name());
            tokenById.setAccess_token(jwt);
            tokenRepository.save(tokenById);
            authCodeRepository.deleteById(tokenRequest.getCode());

            TokenResponse tokenResponse = TokenResponse.builder()
                    .access_token(jwt)
                    .refresh_token(tokenId)
                    .token_type("bearer")
                    .expires_in(28800)
                    .scope(authCode.get().getScope())
                    .build();
            return tokenResponse;
        } else {
            throw new AuthCodeExpiredException("Auth code expired");
        }
    }

    private String generateJWTToken(AuthCode authCode, String tokenId, ClientConfig clientConfig) throws InvalidKeySpecException, NoSuchAlgorithmException, IOException {
        JwtBuilder jwtBuilder = Jwts.builder();
        JwsHeader jwsHeader = Jwts.jwsHeader();
        jwsHeader.setKeyId("easy1");
        jwsHeader.setAlgorithm("RS256");
        jwtBuilder.setHeader((Map<String, Object>) jwsHeader);
        jwtBuilder.signWith(SignatureAlgorithm.RS256, cryptoService.getPrivateKey());
        jwtBuilder.setSubject(authCode.getUser_id());
        jwtBuilder.setIssuer("easyiam");
        jwtBuilder.setExpiration(DateTime.now().plusSeconds(28800).toDate());
        jwtBuilder.setIssuedAt(DateTime.now().toDate());
        jwtBuilder.setId(tokenId);
        jwtBuilder.claim("scope", authCode.getScope());
        jwtBuilder.claim("eid", authCode.getUser_name());

        return jwtBuilder.compact();
    }
}
