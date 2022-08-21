package com.easy.iam.repository;

import com.easy.iam.model.AuthCode;
import com.easy.iam.model.WebAuthnRegistrationRequest;
import org.springframework.data.repository.CrudRepository;

public interface WebAuthnRegistrationRequestRepository extends CrudRepository<WebAuthnRegistrationRequest, String> {
}
