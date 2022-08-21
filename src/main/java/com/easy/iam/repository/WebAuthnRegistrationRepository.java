package com.easy.iam.repository;

import com.easy.iam.model.WebAuthnRegistration;
import org.springframework.data.repository.CrudRepository;

public interface WebAuthnRegistrationRepository extends CrudRepository<WebAuthnRegistration, String> {
}
