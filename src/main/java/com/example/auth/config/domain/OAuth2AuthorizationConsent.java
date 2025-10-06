package com.example.auth.config.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.*;

import java.io.Serial;
import java.io.Serializable;


@Entity
@Table(name = "oauth2_authorization_consent")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class OAuth2AuthorizationConsent implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    @Id
    @Column(name = "registered_client_id", length = 100, nullable = false)
    private String registeredClientId;

    @Id
    @Column(name = "principal_name", length = 200, nullable = false)
    private String principalName;

    @Column(name = "authorities", nullable = false, length = 4000, columnDefinition = "TEXT")
    private String authorities;

}
