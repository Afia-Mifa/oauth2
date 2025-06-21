package com.example.auth.config.service;

import com.example.auth.config.domain.AppUser;
import com.example.auth.config.domain.Privilege;
import com.example.auth.config.domain.Role;
import com.example.auth.config.repository.AppUserRepository;
import com.example.auth.config.repository.PrivilegeRepository;
import com.example.auth.config.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

@Component
@RequiredArgsConstructor
public class ApplicationInitializerService {

    @Value("${application.data.initialize}")
    private boolean shouldInitialize;

    private final PasswordEncoder passwordEncoder;

    private final AppUserRepository appUserRepository;

    private final PrivilegeRepository privilegeRepository;

    private final RoleRepository roleRepository;

    @Bean
    CommandLineRunner init(RegisteredClientRepository repository) {
        return args -> {
            if (!shouldInitialize) {
                System.out.print("Skipped initialization");
                return;
            }

            AppUser appUser = appUserRepository.findByUserName("root").orElseGet(AppUser::new);

            if (appUser.isNew()) {
                Privilege read = new Privilege();
                read.setName("read");

                Privilege write = new Privilege();
                write.setName("write");
                privilegeRepository.save(read);
                privilegeRepository.save(write);

                Role role = new Role();
                role.setName("Root");
                role.setPrivileges(new HashSet<>(List.of(read, write)));
                roleRepository.save(role);

                appUser.setUserName("root");
                appUser.setName("Root");
                appUser.setPasswordHash(passwordEncoder.encode("root"));
                appUser.setRoles(Set.of(role));

                appUserRepository.save(appUser);
            }

            RegisteredClient client = RegisteredClient.withId(UUID.randomUUID().toString())
                    .clientId("my-client")
                    .clientSecret("{noop}secret")
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .redirectUri("http://localhost:8080/auth/callback")
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                    .scope(OidcScopes.OPENID)
                    .scope(OidcScopes.PROFILE)
                    .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
                    .build();
            repository.save(client);
        };
    }
}
