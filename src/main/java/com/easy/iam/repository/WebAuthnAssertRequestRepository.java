package com.easy.iam.repository;

import com.easy.iam.model.WebAuthnAssertRequest;
import org.springframework.data.repository.CrudRepository;

public interface WebAuthnAssertRequestRepository extends CrudRepository<WebAuthnAssertRequest, String> {
}
