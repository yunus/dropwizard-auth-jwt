package com.github.toastshaman.dropwizard.auth.jwt;

import io.dropwizard.auth.AuthenticationException;
import io.dropwizard.auth.Authenticator;
import io.dropwizard.auth.Authorizer;
import io.dropwizard.auth.PrincipalImpl;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.consumer.JwtContext;

import com.google.common.base.Optional;

import java.security.Principal;
import java.util.List;


public class AuthUtil {

    public static Authenticator<JwtContext, Principal> getJWTAuthenticator(final List<String> validUsers) {
        return context -> {
            try {
                final String subject = context.getJwtClaims().getSubject();

                if (validUsers.contains(subject)) {
                    return Optional.of(new PrincipalImpl(subject));
                }

                if ("bad-guy".equals(subject)) {
                    throw new AuthenticationException("CRAP");
                }

                return Optional.absent();
            } catch (MalformedClaimException e) {
                return Optional.absent();
            }
        };
    }

    public static Authorizer<Principal> getTestAuthorizer(final String validUser, final String validRole) {
        return (principal, role) -> principal != null && validUser.equals(principal.getName()) && validRole.equals(role);
    }
}