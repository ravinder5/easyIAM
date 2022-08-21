// Copyright (c) 2018, Yubico AB
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package com.easy.iam.webauthn.service;

import com.easy.iam.model.WebAuthnAssertRequest;
import com.easy.iam.model.WebAuthnRegistrationRequest;
import com.easy.iam.repository.WebAuthnAssertRequestRepository;
import com.easy.iam.repository.WebAuthnRegistrationRequestRepository;
import com.easy.iam.webauthn.config.Config;
import com.easy.iam.webauthn.data.*;
import com.easy.iam.yubico.util.Either;
import com.easy.iam.yubico.webauthn.attestation.resolver.SimpleTrustResolverWithEquality;
import com.fasterxml.jackson.annotation.JsonAutoDetect.Visibility;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jdk8.Jdk8Module;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.gson.Gson;
import com.yubico.internal.util.CertificateParser;
import com.yubico.internal.util.WebAuthnCodecs;
import com.yubico.webauthn.*;
import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.RegistrationResult;
import com.yubico.webauthn.attestation.*;
import com.yubico.webauthn.data.*;
import com.yubico.webauthn.exception.AssertionFailedException;
import com.yubico.webauthn.exception.RegistrationFailedException;
import lombok.NonNull;
import lombok.Value;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import java.util.function.Supplier;

import static com.fasterxml.jackson.annotation.JsonInclude.Include;

@Service
public class WebAuthnService {
    private static final Logger logger = LoggerFactory.getLogger(WebAuthnService.class);
    private static final SecureRandom random = new SecureRandom();
    @Autowired
    ObjectMapper objectMapper;

    private static final String PREVIEW_METADATA_PATH = "/preview-metadata.json";

    private final Cache<AssertionRequestWrapper, AuthenticatedAction> authenticatedActions = newCache();
    @Autowired
    private RegistrationStorage userStorage;
    @Autowired
    private WebAuthnRegistrationRequestRepository webAuthnRegistrationRequestRepository;
    @Autowired
    private WebAuthnAssertRequestRepository webAuthnAssertRequestRepository;

    private final Clock clock = Clock.systemDefaultZone();
    private final ObjectMapper jsonMapper = WebAuthnCodecs.json();

    private static ByteArray generateRandom(int length) {
        byte[] bytes = new byte[length];
        random.nextBytes(bytes);
        return new ByteArray(bytes);
    }

    private static <K, V> Cache<K, V> newCache() {
        return CacheBuilder.newBuilder()
            .maximumSize(100)
            .expireAfterAccess(10, TimeUnit.MINUTES)
            .build();
    }

    public Either<String, RegistrationRequest> startRegistration(
            @NonNull String username,
            @NonNull String displayName,
            Optional<String> credentialNickname,
            boolean requireResidentKey
        ) {
            logger.trace("startRegistration username: {}, credentialNickname: {}", username, credentialNickname);

            if (username == null || username.isEmpty()) {
                return Either.left("username must not be empty.");
            }

            Collection<CredentialRegistration> registrations = userStorage.getRegistrationsByUsername(username);

            UserIdentity user;

            if (registrations.isEmpty()) {
                user = UserIdentity.builder()
                    .name(username)
                    .displayName(displayName)
                    .id(generateRandom(32))
                    .build();
            } else {
                return Either.left("username already registered for FIDO.");
            }

            RelyingParty rp = RelyingParty.builder()
                .identity(Config.getRpIdentity())
                .credentialRepository(userStorage)
                .origins(Config.getOrigins())
                .attestationConveyancePreference(Optional.of(AttestationConveyancePreference.DIRECT))
                .metadataService(Optional.of(Config.getMetaDataService()))
                .allowUnrequestedExtensions(true)
                .allowUntrustedAttestation(true)
                .validateSignatureCounter(true)
                .appId(Config.getAppId())
                .build();

            RegistrationRequest request = new RegistrationRequest(
                username,
                credentialNickname,
                generateRandom(32),
                rp.startRegistration(
                    StartRegistrationOptions.builder()
                        .user(user)
                        .authenticatorSelection(Optional.of(AuthenticatorSelectionCriteria.builder()
                            .requireResidentKey(requireResidentKey)
                            .authenticatorAttachment(AuthenticatorAttachment.CROSS_PLATFORM)    // Default to roaming security keys (CROSS_PLATFORM). Comment out this line to enable either PLATFORM or CROSS_PLATFORM authenticators
                            .build()
                        ))
                        .build()
                )
            );

        try {
            Gson gson = new Gson();
            webAuthnRegistrationRequestRepository.save(new WebAuthnRegistrationRequest(request.getRequestId().toString(), gson.toJson(request)));
        } catch (Exception e) {
            e.printStackTrace();
        }

        return Either.right(request);
    }

    public <T> Either<List<String>, AssertionRequestWrapper> startAddCredential(
        @NonNull String username,
        Optional<String> credentialNickname,
        boolean requireResidentKey,
        Function<RegistrationRequest, Either<List<String>, T>> whenAuthenticated
    ) {
        logger.trace("startAddCredential username: {}, credentialNickname: {}, requireResidentKey: {}", username, credentialNickname, requireResidentKey);

        if (username == null || username.isEmpty()) {
            return Either.left(Collections.singletonList("username must not be empty."));
        }

        Collection<CredentialRegistration> registrations = userStorage.getRegistrationsByUsername(username);

        if (registrations.isEmpty()) {
            return Either.left(Collections.singletonList("The username \"" + username + "\" is not registered."));
        } else {
            final UserIdentity existingUser = registrations.stream().findAny().get().getUserIdentity();

            RelyingParty rp = RelyingParty.builder()
                    .identity(Config.getRpIdentity())
                    .credentialRepository(userStorage)
                    .origins(Config.getOrigins())
                    .attestationConveyancePreference(Optional.of(AttestationConveyancePreference.DIRECT))
                    .metadataService(Optional.of(Config.getMetaDataService()))
                    .allowUnrequestedExtensions(true)
                    .allowUntrustedAttestation(true)
                    .validateSignatureCounter(true)
                    .appId(Config.getAppId())
                    .build();
            AuthenticatedAction<T> action = (SuccessfulAuthenticationResult result) -> {
                RegistrationRequest request = new RegistrationRequest(
                    username,
                    credentialNickname,
                    generateRandom(32),
                    rp.startRegistration(
                        StartRegistrationOptions.builder()
                            .user(existingUser)
                            .authenticatorSelection(AuthenticatorSelectionCriteria.builder()
                                .requireResidentKey(requireResidentKey)
                                .build()
                            )
                            .build()
                    )
                );
                try {
                    webAuthnRegistrationRequestRepository.save(new WebAuthnRegistrationRequest(request.getRequestId().toString(), objectMapper.writeValueAsString(request)));
                } catch (JsonProcessingException e) {
                    e.printStackTrace();
                }

                return whenAuthenticated.apply(request);
            };

            return startAuthenticatedAction(Optional.of(username), action);
        }
    }

    @Value
    public static class SuccessfulRegistrationResult {
        final boolean success = true;
        RegistrationRequest request;
        RegistrationResponse response;
        CredentialRegistration registration;
        boolean attestationTrusted;
        Optional<AttestationCertInfo> attestationCert;

        public SuccessfulRegistrationResult(RegistrationRequest request, RegistrationResponse response, CredentialRegistration registration, boolean attestationTrusted) {
            this.request = request;
            this.response = response;
            this.registration = registration;
            this.attestationTrusted = attestationTrusted;
            attestationCert = Optional.ofNullable(
                response.getCredential().getResponse().getAttestation().getAttestationStatement().get("x5c")
            ).map(certs -> certs.get(0))
            .flatMap((JsonNode certDer) -> {
                try {
                    return Optional.of(new ByteArray(certDer.binaryValue()));
                } catch (IOException e) {
                    logger.error("Failed to get binary value from x5c element: {}", certDer, e);
                    return Optional.empty();
                }
            })
            .map(AttestationCertInfo::new);
        }
    }

    @Value
    public class SuccessfulU2fRegistrationResult {
        final boolean success = true;
        final RegistrationRequest request;
        final U2fRegistrationResponse response;
        final CredentialRegistration registration;
        boolean attestationTrusted;
        Optional<AttestationCertInfo> attestationCert;
    }

    @Value
    public static class AttestationCertInfo {
        final ByteArray der;
        final String text;
        public AttestationCertInfo(ByteArray certDer) {
            der = certDer;
            X509Certificate cert = null;
            try {
                cert = CertificateParser.parseDer(certDer.getBytes());
            } catch (CertificateException e) {
                logger.error("Failed to parse attestation certificate");
            }
            if (cert == null) {
                text = null;
            } else {
                text = cert.toString();
            }
        }
    }

    public Either<List<String>, SuccessfulRegistrationResult> finishRegistration(String responseJson) {
        logger.trace("finishRegistration responseJson: {}", responseJson);
        RegistrationResponse response = null;
        try {
            response = jsonMapper.readValue(responseJson, RegistrationResponse.class);
        } catch (IOException e) {
            logger.error("JSON error in finishRegistration; responseJson: {}", responseJson, e);
            return Either.left(Arrays.asList("Registration failed!", "Failed to decode response object.", e.getMessage()));
        }
        RegistrationRequest request = null;
        Optional<WebAuthnRegistrationRequest> webAuthnRegistrationRequest = webAuthnRegistrationRequestRepository.findById(response.getRequestId().toString());
        if (webAuthnRegistrationRequest.isPresent()) {
            try {
                Gson gson = new Gson();
                request = gson.fromJson(webAuthnRegistrationRequest.get().getRegistration_data(), RegistrationRequest.class);
                webAuthnRegistrationRequestRepository.delete(webAuthnRegistrationRequest.get());
            } catch (Exception e) {
                logger.error("JSON error in finishRegistration; responseJson: {}", responseJson, e);
            }
        }

        if (request == null) {
            logger.debug("fail finishRegistration responseJson: {}", responseJson);
            return Either.left(Arrays.asList("Registration failed!", "No such registration in progress."));
        } else {
            try {
                RelyingParty rp = RelyingParty.builder()
                        .identity(Config.getRpIdentity())
                        .credentialRepository(userStorage)
                        .origins(Config.getOrigins())
                        .attestationConveyancePreference(Optional.of(AttestationConveyancePreference.DIRECT))
                        .metadataService(Optional.of(Config.getMetaDataService()))
                        .allowUnrequestedExtensions(true)
                        .allowUntrustedAttestation(true)
                        .validateSignatureCounter(false)
                        .appId(Config.getAppId())
                        .build();
                RegistrationResult registration = rp.finishRegistration(
                    FinishRegistrationOptions.builder()
                        .request(request.getPublicKeyCredentialCreationOptions())
                        .response(response.getCredential())
                        .build()
                );

                return Either.right(
                    new SuccessfulRegistrationResult(
                        request,
                        response,
                        addRegistration(
                            request.getPublicKeyCredentialCreationOptions().getUser(),
                            request.getCredentialNickname(),
                            response,
                            registration
                        ),
                        registration.isAttestationTrusted()
                    )
                );
            } catch (RegistrationFailedException e) {
                logger.debug("fail finishRegistration responseJson: {}", responseJson, e);
                return Either.left(Arrays.asList("Registration failed!", e.getMessage()));
            } catch (Exception e) {
                logger.error("fail finishRegistration responseJson: {}", responseJson, e);
                return Either.left(Arrays.asList("Registration failed unexpectedly; this is likely a bug.", e.getMessage()));
            }
        }
    }

    public Either<List<String>, AssertionRequestWrapper> startAuthentication(Optional<String> username) {
        logger.trace("startAuthentication username: {}", username);

        if (username.isPresent() && userStorage.getRegistrationsByUsername(username.get()).isEmpty()) {
            return Either.left(Collections.singletonList("The username \"" + username.get() + "\" is not registered."));
        } else {
            RelyingParty rp = RelyingParty.builder()
                    .identity(Config.getRpIdentity())
                    .credentialRepository(userStorage)
                    .origins(Config.getOrigins())
                    .attestationConveyancePreference(Optional.of(AttestationConveyancePreference.DIRECT))
                    .metadataService(Optional.of(Config.getMetaDataService()))
                    .allowUnrequestedExtensions(true)
                    .allowUntrustedAttestation(true)
                    .validateSignatureCounter(true)
                    .appId(Config.getAppId())
                    .build();
            AssertionRequestWrapper request = new AssertionRequestWrapper(
                generateRandom(32),
                rp.startAssertion(
                    StartAssertionOptions.builder()
                        .username(username)
                        .build()
                )
            );
            try {
                Gson gson = new Gson();
                webAuthnAssertRequestRepository.save(new WebAuthnAssertRequest(request.getRequestId().toString(), gson.toJson(request)));
            } catch (Exception e) {
                e.printStackTrace();
            }
            return Either.right(request);
        }
    }

    @Value
    public static class SuccessfulAuthenticationResult {
        final boolean success = true;
        AssertionRequestWrapper request;
        AssertionResponse response;
        Collection<CredentialRegistration> registrations;
        List<String> warnings;
    }

    public Either<List<String>, SuccessfulAuthenticationResult> finishAuthentication(String responseJson) {
        logger.trace("finishAuthentication responseJson: {}", responseJson);

        final AssertionResponse response;
        try {
            response = jsonMapper.readValue(responseJson, AssertionResponse.class);
        } catch (IOException e) {
            logger.debug("Failed to decode response object", e);
            return Either.left(Arrays.asList("Assertion failed!", "Failed to decode response object.", e.getMessage()));
        }



        AssertionRequestWrapper request = null;

        Optional<WebAuthnAssertRequest> webAuthnAssertRequest = webAuthnAssertRequestRepository.findById(response.getRequestId().toString());
        if (webAuthnAssertRequest.isPresent()) {
            try {
                Gson gson = new Gson();
                request = gson.fromJson(webAuthnAssertRequest.get().getAssertation_data(), AssertionRequestWrapper.class);
                webAuthnAssertRequestRepository.delete(webAuthnAssertRequest.get());
            } catch (Exception e) {
                logger.error("JSON error in finishRegistration; responseJson: {}", responseJson, e);
            }
        }

        if (request == null) {
            return Either.left(Arrays.asList("Assertion failed!", "No such assertion in progress."));
        } else {
            try {
                RelyingParty rp = RelyingParty.builder()
                        .identity(Config.getRpIdentity())
                        .credentialRepository(userStorage)
                        .origins(Config.getOrigins())
                        .attestationConveyancePreference(Optional.of(AttestationConveyancePreference.DIRECT))
                        .metadataService(Optional.of(Config.getMetaDataService()))
                        .allowUnrequestedExtensions(true)
                        .allowUntrustedAttestation(true)
                        .validateSignatureCounter(true)
                        .appId(Config.getAppId())
                        .build();
                AssertionResult result = rp.finishAssertion(
                    FinishAssertionOptions.builder()
                        .request(AssertionRequest.builder().publicKeyCredentialRequestOptions(request.getPublicKeyCredentialRequestOptions())
                                .username(request.getUsername()).build())
                        .response(response.getCredential())
                        .build()
                );

                if (result.isSuccess()) {
                    //ToDO: try to update signature verification count
                    return Either.right(
                        new SuccessfulAuthenticationResult(
                            request,
                            response,
                            userStorage.getRegistrationsByUsername(result.getUsername()),
                            result.getWarnings()
                        )
                    );
                } else {
                    return Either.left(Collections.singletonList("Assertion failed: Invalid assertion."));
                }
            } catch (AssertionFailedException e) {
                logger.debug("Assertion failed", e);
                return Either.left(Arrays.asList("Assertion failed!", e.getMessage()));
            } catch (Exception e) {
                logger.error("Assertion failed", e);
                return Either.left(Arrays.asList("Assertion failed unexpectedly; this is likely a bug.", e.getMessage()));
            }
        }
    }

    public Either<List<String>, AssertionRequestWrapper> startAuthenticatedAction(Optional<String> username, AuthenticatedAction<?> action) {
        return startAuthentication(username)
            .map(request -> {
                synchronized (authenticatedActions) {
                    authenticatedActions.put(request, action);
                }
                return request;
            });
    }

    public Either<List<String>, ?> finishAuthenticatedAction(String responseJson) {
        return finishAuthentication(responseJson)
            .flatMap(result -> {
                AuthenticatedAction<?> action = authenticatedActions.getIfPresent(result.request);
                authenticatedActions.invalidate(result.request);
                if (action == null) {
                    return Either.left(Collections.singletonList(
                        "No action was associated with assertion request ID: " + result.getRequest().getRequestId()
                    ));
                } else {
                    return action.apply(result);
                }
            });
    }

    public <T> Either<List<String>, AssertionRequestWrapper> deregisterCredential(String username, ByteArray credentialId, Function<CredentialRegistration, T> resultMapper) {
        logger.trace("deregisterCredential username: {}, credentialId: {}", username, credentialId);

        if (username == null || username.isEmpty()) {
            return Either.left(Collections.singletonList("Username must not be empty."));
        }

        if (credentialId == null || credentialId.getBytes().length == 0) {
            return Either.left(Collections.singletonList("Credential ID must not be empty."));
        }

        AuthenticatedAction<T> action = (SuccessfulAuthenticationResult result) -> {
            Optional<CredentialRegistration> credReg = userStorage.getRegistrationByUsernameAndCredentialId(username, credentialId);

            if (credReg.isPresent()) {
                userStorage.removeRegistrationByUsername(username, credReg.get());
                return Either.right(resultMapper.apply(credReg.get()));
            } else {
                return Either.left(Collections.singletonList("Credential ID not registered:" + credentialId));
            }
        };

        return startAuthenticatedAction(Optional.of(username), action);
    }

    public <T> Either<List<String>, T> deleteAccount(String username, Supplier<T> onSuccess) {
        logger.trace("deleteAccount username: {}", username);

        if (username == null || username.isEmpty()) {
            return Either.left(Collections.singletonList("Username must not be empty."));
        }

        boolean removed = userStorage.removeAllRegistrations(username);

        if (removed) {
            return Either.right(onSuccess.get());
        } else {
            return Either.left(Collections.singletonList("Username not registered:" + username));
        }
    }

    private CredentialRegistration addRegistration(
        UserIdentity userIdentity,
        Optional<String> nickname,
        RegistrationResponse response,
        RegistrationResult result
    ) {
        return addRegistration(
            userIdentity,
            nickname,
            response.getCredential().getResponse().getAttestation().getAuthenticatorData().getSignatureCounter(),
            RegisteredCredential.builder()
                .credentialId(result.getKeyId().getId())
                .userHandle(userIdentity.getId())
                .publicKeyCose(result.getPublicKeyCose())
                .signatureCount(response.getCredential().getResponse().getParsedAuthenticatorData().getSignatureCounter())
                .build(),
            result.getAttestationMetadata()
        );
    }

    private CredentialRegistration addRegistration(
        UserIdentity userIdentity,
        Optional<String> nickname,
        long signatureCount,
        U2fRegistrationResult result
    ) {
        return addRegistration(
            userIdentity,
            nickname,
            signatureCount,
            RegisteredCredential.builder()
                .credentialId(result.getKeyId().getId())
                .userHandle(userIdentity.getId())
                .publicKeyCose(result.getPublicKeyCose())
                .signatureCount(signatureCount)
                .build(),
            result.getAttestationMetadata()
        );
    }

    private CredentialRegistration addRegistration(
        UserIdentity userIdentity,
        Optional<String> nickname,
        long signatureCount,
        RegisteredCredential credential,
        Optional<Attestation> attestationMetadata
    ) {
        CredentialRegistration reg = CredentialRegistration.builder()
            .userIdentity(userIdentity)
            .credentialNickname(nickname)
            .registrationTime(clock.instant())
            .credential(credential)
            .signatureCount(signatureCount)
            .attestationMetadata(attestationMetadata)
            .build();

        logger.debug(
            "Adding registration: user: {}, nickname: {}, credential: {}",
            userIdentity,
            nickname,
            credential
        );
        userStorage.addRegistrationByUsername(userIdentity.getName(), reg);
        return reg;
    }

    public Collection<CredentialRegistration> getRegistrationsByUsername(String username) {
        return this.userStorage.getRegistrationsByUsername(username);
    }

}
