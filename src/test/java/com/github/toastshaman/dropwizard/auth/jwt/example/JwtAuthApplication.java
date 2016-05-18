package com.github.toastshaman.dropwizard.auth.jwt.example;

import java.security.Principal;

import org.glassfish.jersey.server.filter.RolesAllowedDynamicFeature;

import com.github.toastshaman.dropwizard.auth.jwt.JwtAuthFilter;
import com.github.yunus.dropwizard.auth.jwt.JWKSetGenerator;
import com.github.yunus.dropwizard.auth.jwt.WSO2CustomClaimsVerifier;
import com.google.common.base.Optional;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SimpleSecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

import io.dropwizard.Application;
import io.dropwizard.auth.AuthDynamicFeature;
import io.dropwizard.auth.AuthValueFactoryProvider;
import io.dropwizard.auth.Authenticator;
import io.dropwizard.auth.PrincipalImpl;
import io.dropwizard.setup.Bootstrap;
import io.dropwizard.setup.Environment;

/**
 * A sample dropwizard application that shows how to set up the JWT Authentication provider.
 * <p/>
 * The Authentication Provider will parse the tokens supplied in the "Authorization" HTTP header in each HTTP request
 * given your resource is protected with the @Auth annotation.
 */
public class JwtAuthApplication extends Application<MyConfiguration> {

    @Override
    public void initialize(Bootstrap<MyConfiguration> configurationBootstrap) {}

    @Override
    public void run(MyConfiguration configuration, Environment environment) throws Exception {
        
    	// This example is for JWS

        JWKSource<SimpleSecurityContext> keySource = new ImmutableJWKSet<>(JWKSetGenerator.fromX509Jks(configuration.getJwtTokenCertsfile(), null));
		JWSAlgorithm expectedJWSAlg = JWSAlgorithm.RS256;
		JWSKeySelector<SimpleSecurityContext> keySelector = new JWSVerificationKeySelector<>(expectedJWSAlg, keySource);

		ConfigurableJWTProcessor<SimpleSecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
		jwtProcessor.setJWSKeySelector(keySelector);
		jwtProcessor.setJWTClaimsVerifier(new WSO2CustomClaimsVerifier());

		        environment.jersey().register(new AuthDynamicFeature(
		            new JwtAuthFilter.Builder<Principal>()
		                .setJwtConsumer(jwtProcessor)
		                .setAuthorizationHeader("x-jwt-assertion")
		                .setRealm("realm")
		                .setPrefix("Bearer")		               
		                .setAuthenticator(new ExampleAuthenticator())		                
		                .buildAuthFilter()));

        environment.jersey().register(new AuthValueFactoryProvider.Binder<>(Principal.class));
        environment.jersey().register(RolesAllowedDynamicFeature.class);
       
    }

    private static class ExampleAuthenticator implements Authenticator<JWTClaimsSet, Principal> {

        @Override
        public Optional<Principal> authenticate(JWTClaimsSet context) {
            // Provide your own implementation to lookup users based on the principal attribute in the
            // JWT Token. E.g.: lookup users from a database etc.
            // This method will be called once the token's signature has been verified

            // In case you want to verify different parts of the token you can do that here.
            // E.g.: Verifying that the provided token has not expired.

            // All JsonWebTokenExceptions will result in a 401 Unauthorized response.

            try {
                final String subject = context.getSubject();
                if ("good-guy".equals(subject)) {
                    return Optional.of(new PrincipalImpl("good-guy"));
                }
                return Optional.absent();
            }
            catch (Exception e) { return Optional.absent(); }
        }
    }

    public static void main(String[] args) throws Exception {
        new JwtAuthApplication().run("server");
    }
}
