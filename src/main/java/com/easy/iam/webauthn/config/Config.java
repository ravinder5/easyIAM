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

package com.easy.iam.webauthn.config;

import com.easy.iam.webauthn.service.RegistrationStorage;
import com.easy.iam.webauthn.service.WebAuthnService;
import com.easy.iam.yubico.webauthn.attestation.resolver.SimpleTrustResolverWithEquality;
import com.google.common.io.Closeables;
import com.yubico.internal.util.CollectionUtil;
import com.yubico.internal.util.ExceptionUtil;
import com.yubico.internal.util.WebAuthnCodecs;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.attestation.*;
import com.yubico.webauthn.attestation.resolver.CompositeAttestationResolver;
import com.yubico.webauthn.attestation.resolver.CompositeTrustResolver;
import com.yubico.webauthn.attestation.resolver.SimpleAttestationResolver;
import com.yubico.webauthn.data.AttestationConveyancePreference;
import com.yubico.webauthn.data.RelyingPartyIdentity;
import com.yubico.webauthn.extension.appid.AppId;
import com.yubico.webauthn.extension.appid.InvalidAppIdException;
import jnr.ffi.annotations.Meta;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.cert.CertificateException;
import java.util.*;

public class Config {

    private static final Logger logger = LoggerFactory.getLogger(Config.class);
    private static final String PREVIEW_METADATA_PATH = "/preview-metadata.json";
//    private static final String DEFAULT_ORIGIN = "https://localhost:8443";
    private static final String DEFAULT_ORIGIN = "https://localhost:3000";
    private static final int DEFAULT_PORT = 8080;
    private static final RelyingPartyIdentity DEFAULT_RP_ID
        = RelyingPartyIdentity.builder().id("localhost").name("Yubico WebAuthn demo").build();

    private final Set<String> origins;
    private final int port;
    private final RelyingPartyIdentity rpIdentity;
    private final Optional<AppId> appId;

    private final MetadataService metadataService;

    private Config(Set<String> origins, int port, RelyingPartyIdentity rpIdentity, Optional<AppId> appId, MetadataService metadataService) {
        this.origins = CollectionUtil.immutableSet(origins);
        this.port = port;
        this.rpIdentity = rpIdentity;
        this.appId = appId;
        this.metadataService = metadataService;
    }

    private static Config instance;
    private static Config getInstance() {
        if (instance == null) {
            try {
                instance = new Config(computeOrigins(), computePort(), computeRpIdentity(), computeAppId(), computeStandardMetadataService());
            } catch (MalformedURLException e) {
                throw new RuntimeException(e);
            } catch (InvalidAppIdException e) {
                throw new RuntimeException(e);
            } catch (CertificateException e) {
                throw new RuntimeException(e);
            }
        }
        return instance;
    }
    /**
     * Create a {@link TrustResolver} that accepts attestation certificates that are directly recognised as trust anchors.
     */
    private static TrustResolver createExtraTrustResolver() {
        try {
            MetadataObject metadata = readPreviewMetadata();
            return new SimpleTrustResolverWithEquality(metadata.getParsedTrustedCertificates());
        } catch (CertificateException e) {
            throw ExceptionUtil.wrapAndLog(logger, "Failed to read trusted certificate(s)", e);
        }
    }
    private static MetadataObject readPreviewMetadata() {
        InputStream is = Config.class.getResourceAsStream(PREVIEW_METADATA_PATH);
        try {
            return WebAuthnCodecs.json().readValue(is, MetadataObject.class);
        } catch (IOException e) {
            throw ExceptionUtil.wrapAndLog(logger, "Failed to read metadata from " + PREVIEW_METADATA_PATH, e);
        } finally {
            Closeables.closeQuietly(is);
        }
    }

    /**
     * Create a {@link AttestationResolver} with additional metadata for unreleased YubiKey Preview devices.
     */
    private static AttestationResolver createExtraMetadataResolver(TrustResolver trustResolver) {
        try {
            MetadataObject metadata = readPreviewMetadata();
            return new SimpleAttestationResolver(Collections.singleton(metadata), trustResolver);
        } catch (CertificateException e) {
            throw ExceptionUtil.wrapAndLog(logger, "Failed to read trusted certificate(s)", e);
        }
    }

    public static Set<String> getOrigins() {
        return getInstance().origins;
    }

    public static int getPort() {
        return getInstance().port;
    }

    public static RelyingPartyIdentity getRpIdentity() {
        return getInstance().rpIdentity;
    }

    public static Optional<AppId> getAppId() {
        return getInstance().appId;
    }

    public static MetadataService getMetaDataService() {
        return getInstance().metadataService;
    }

    private static StandardMetadataService computeStandardMetadataService() throws CertificateException {
        TrustResolver trustResolver = new CompositeTrustResolver(Arrays.asList(
                StandardMetadataService.createDefaultTrustResolver(),
                createExtraTrustResolver()
        ));
        return new StandardMetadataService(
                new CompositeAttestationResolver(Arrays.asList(
                        StandardMetadataService.createDefaultAttestationResolver(trustResolver),
                        createExtraMetadataResolver(trustResolver)
                ))
        );
    }

    private static Set<String> computeOrigins() {
        final String origins = System.getenv("YUBICO_WEBAUTHN_ALLOWED_ORIGINS");

        logger.debug("YUBICO_WEBAUTHN_ALLOWED_ORIGINS: {}", origins);

        final Set<String> result;

        if (origins == null) {
            result = Collections.singleton(DEFAULT_ORIGIN);
        } else {
            result = new HashSet<>(Arrays.asList(origins.split(",")));
        }

        logger.info("Origins: {}", result);

        return result;
    }

    private static int computePort() {
        final String port = System.getenv("YUBICO_WEBAUTHN_PORT");

        if (port == null) {
            return DEFAULT_PORT;
        } else {
            return Integer.parseInt(port);
        }
    }

    private static RelyingPartyIdentity computeRpIdentity() throws MalformedURLException {
        final String name = System.getenv("YUBICO_WEBAUTHN_RP_NAME");
        final String id = System.getenv("YUBICO_WEBAUTHN_RP_ID");
        final String icon = System.getenv("YUBICO_WEBAUTHN_RP_ICON");

        logger.debug("RP name: {}", name);
        logger.debug("RP ID: {}", id);
        logger.debug("RP icon: {}", icon);

        RelyingPartyIdentity.RelyingPartyIdentityBuilder resultBuilder = DEFAULT_RP_ID.toBuilder();

        if (name == null) {
            logger.debug("RP name not given - using default.");
        } else {
            resultBuilder.name(name);
        }

        if (id == null) {
            logger.debug("RP ID not given - using default.");
        } else {
            resultBuilder.id(id);
        }

        if (icon == null) {
            logger.debug("RP icon not given - using none.");
        } else {
            try {
            resultBuilder.icon(Optional.of(new URL(icon)));
            } catch (MalformedURLException e) {
                logger.error("Invalid icon URL: {}", icon, e);
                throw e;
            }
        }

        final RelyingPartyIdentity result = resultBuilder.build();
        logger.info("RP identity: {}", result);
        return result;
    }

    private static Optional<AppId> computeAppId() throws InvalidAppIdException {
        final String appId = System.getenv("YUBICO_WEBAUTHN_U2F_APPID");
        logger.debug("YUBICO_WEBAUTHN_U2F_APPID: {}", appId);

        AppId result = appId == null
            ? new AppId("https://localhost:3000")
            : new AppId(appId);

        logger.debug("U2F AppId: {}", result.getId());
        return Optional.of(result);
    }

}
