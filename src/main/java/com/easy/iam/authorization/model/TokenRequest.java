package com.easy.iam.authorization.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@AllArgsConstructor
@Data
@Builder
public class TokenRequest {
    private String grant_type;
    private String code;
    private String client_id;
    private String client_secret;
}
