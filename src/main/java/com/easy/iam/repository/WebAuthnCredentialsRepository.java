package com.easy.iam.repository;

import com.easy.iam.model.WebAuthnCredentials;
import com.easy.iam.model.WebAuthnRegistration;
import org.springframework.data.repository.CrudRepository;

public interface WebAuthnCredentialsRepository extends CrudRepository<WebAuthnCredentials, String> {
}
