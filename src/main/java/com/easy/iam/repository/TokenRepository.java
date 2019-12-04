package com.easy.iam.repository;

import com.easy.iam.model.TokenById;
import org.springframework.data.repository.CrudRepository;

public interface TokenRepository extends CrudRepository<TokenById, String> {
}
