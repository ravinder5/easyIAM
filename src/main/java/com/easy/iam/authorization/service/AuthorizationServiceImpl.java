package com.easy.iam.authorization.service;

import com.easy.iam.authorization.model.TokenRequest;
import com.easy.iam.authorization.model.TokenResponse;
import com.easy.iam.encryption.CryptoService;
import com.easy.iam.model.AuthCode;
import com.easy.iam.model.ClientConfig;
import com.easy.iam.model.Token;
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
    public TokenResponse generateTokens(TokenRequest tokenRequest) throws InvalidKeySpecException, NoSuchAlgorithmException {
        Optional<AuthCode> authCode = authCodeRepository.findById(tokenRequest.getCode());
        Optional<ClientConfig> clientConfig = clientConfigRepository.findById(tokenRequest.getClient_id());
        if (authCode.isPresent()) {
            String tokenId = UUID.randomUUID().toString();
            String jwt = generateJWTToken(authCode.get(), tokenId, clientConfig.get());
            Token token = new Token();
            token.setToken_id(tokenId);
            token.setClient_id(authCode.get().getClient_id());
            token.setScope(authCode.get().getScope());
            token.setUser_id(authCode.get().getUser_id());
            token.setUser_name(authCode.get().getUser_name());
            token.setToken(jwt);
            tokenRepository.save(token);
            authCodeRepository.deleteById(tokenRequest.getCode());

            TokenResponse tokenResponse = TokenResponse.builder()
                    .access_token(jwt)
                    .refresh_token(tokenId)
                    .token_type("bearer")
                    .expires_in(28800)
                    .scope(authCode.get().getScope())
                    .build();
            return tokenResponse;
        }
        return null;
    }

    private String generateJWTToken(AuthCode authCode, String tokenId, ClientConfig clientConfig) throws InvalidKeySpecException, NoSuchAlgorithmException {
        JwtBuilder jwtBuilder = Jwts.builder();
        JwsHeader jwsHeader = Jwts.jwsHeader();
        jwsHeader.setKeyId("eas1");
        jwsHeader.setAlgorithm("RS256");
        jwtBuilder.setHeader((Map<String, Object>) jwsHeader);
        jwtBuilder.signWith(SignatureAlgorithm.RS256, cryptoService.getPrivateKey());
        jwtBuilder.setSubject(authCode.getUser_id());
        jwtBuilder.setIssuer("easyiam");
        jwtBuilder.setExpiration(DateTime.now().plusSeconds(28800).toDate());
        jwtBuilder.setIssuedAt(DateTime.now().toDate());
        jwtBuilder.setId(tokenId);
        jwtBuilder.claim("scope", StringUtils.join(authCode.getScope(), ","));
        jwtBuilder.claim("eid", authCode.getUser_name());

        return jwtBuilder.compact();
    }
}
