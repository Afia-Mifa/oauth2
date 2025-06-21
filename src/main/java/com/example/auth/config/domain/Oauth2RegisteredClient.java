package com.example.auth.config.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Date;

@Entity
@Getter
@Setter
@NoArgsConstructor
@Table(name = "oauth2_registered_client")
public class Oauth2RegisteredClient {
    @Id
    private String id;

    @Column(unique = true, nullable = false)
    private String clientId;

    @Column(name = "client_id_issued_at", nullable = false)
    private Date clientIdIssuedAt;

    @Column(name = "client_secret", length = 4000, columnDefinition = "TEXT")
    private String clientSecret;

    @Column(name = "client_secret_expires_at")
    private Date clientSecretExpiresAt;

    @Column(name = "client_name", length = 200, nullable = false)
    private String clientName;

    @Column(name = "client_authentication_methods", nullable = false, length = 4000, columnDefinition = "TEXT")
    private String clientAuthenticationMethods;

    @Column(name = "authorization_grant_types", nullable = false, length = 4000, columnDefinition = "TEXT")
    private String authorizationGrantTypes;

    @Column(name = "redirect_uris", length = 4000, columnDefinition = "TEXT")
    private String redirectUris;

    @Column(name = "post_logout_redirect_uris", length = 4000, columnDefinition = "TEXT")
    private String postLogoutRedirectUris;

    @Column(name = "scopes", nullable = false, length = 4000, columnDefinition = "TEXT")
    private String scopes;

    @Column(name = "client_settings", nullable = false, length = 4000, columnDefinition = "TEXT")
    private String clientSettings;

    @Column(name = "token_settings", nullable = false, length = 4000, columnDefinition = "TEXT")
    private String tokenSettings;

}
