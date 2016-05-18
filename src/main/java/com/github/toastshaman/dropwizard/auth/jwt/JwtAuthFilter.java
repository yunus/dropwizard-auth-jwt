package com.github.toastshaman.dropwizard.auth.jwt;

import static com.google.common.base.Preconditions.checkNotNull;
import static javax.ws.rs.core.HttpHeaders.AUTHORIZATION;

import java.io.IOException;
import java.security.Principal;
import java.text.ParseException;
import java.util.Map;

import javax.annotation.Priority;
import javax.ws.rs.Priorities;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.core.Cookie;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.SecurityContext;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Optional;
import com.google.common.base.Strings;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;

import io.dropwizard.auth.AuthFilter;
import io.dropwizard.auth.AuthenticationException;
import io.dropwizard.auth.Authenticator;

@Priority(Priorities.AUTHENTICATION)
public class JwtAuthFilter<P extends Principal> extends AuthFilter<JWTClaimsSet, P> {

    private static final Logger LOGGER = LoggerFactory.getLogger(JwtAuthFilter.class);

    private final ConfigurableJWTProcessor  consumer;
    private final String cookieName; 
    private final String customHeader;

    private JwtAuthFilter(ConfigurableJWTProcessor consumer, String cookieName, String header) {
        this.consumer = consumer;
        this.cookieName = cookieName;
        this.customHeader = header;
    }

    @Override
    public void filter(final ContainerRequestContext requestContext) throws IOException {
        final Optional<String> optionalToken = getTokenFromCookieOrHeader(requestContext);

        if (optionalToken.isPresent()) {
            try {
                final JWTClaimsSet jwtClaimsSet = verifyToken(optionalToken.get());
                final Optional<P> principal = authenticator.authenticate(jwtClaimsSet);

                if (principal.isPresent()) {
                    requestContext.setSecurityContext(new SecurityContext() {

                        @Override
                        public Principal getUserPrincipal() {
                            return principal.get();
                        }

                        @Override
                        public boolean isUserInRole(String role) {
                            return authorizer.authorize(principal.get(), role);
                        }

                        @Override
                        public boolean isSecure() {
                            return requestContext.getSecurityContext().isSecure();
                        }

                        @Override
                        public String getAuthenticationScheme() {
                            return SecurityContext.BASIC_AUTH;
                        }

                    });
                    return;
                }
            }  catch (AuthenticationException e) {
                LOGGER.warn("Error authenticating credentials", e);
                throw new WebApplicationException(e.getMessage(), Response.Status.UNAUTHORIZED);
            } catch (ParseException e) {
				LOGGER.warn("Error in parsing JWT. ",e);				
				 throw new WebApplicationException(e.getMessage(), Response.Status.UNAUTHORIZED);
			} catch (BadJOSEException e) {
				LOGGER.warn("Bad JOSE. ",e);				
				 throw new WebApplicationException(e.getMessage(), Response.Status.UNAUTHORIZED);
			} catch (JOSEException e) {
				LOGGER.warn("JOSE exception. ",e);				
				 throw new WebApplicationException(e.getMessage(), Response.Status.UNAUTHORIZED);
			}
        }

        throw new WebApplicationException(unauthorizedHandler.buildResponse(prefix, realm));
    }

    private JWTClaimsSet verifyToken(String rawToken) throws ParseException, BadJOSEException, JOSEException  {
        return consumer.process(rawToken,null);
    }

    private Optional<String> getTokenFromCookieOrHeader(ContainerRequestContext requestContext) {
    	
    	final Optional<String> customHeaderToken = getTokenFromCustomHeader(requestContext.getHeaders());
      
        if (customHeaderToken.isPresent()) {
            return customHeaderToken;
        }
        
        final Optional<String> headerToken = getTokenFromHeader(requestContext.getHeaders());
        if (headerToken.isPresent()) {
            return headerToken;
        }

        final Optional<String> cookieToken = getTokenFromCookie(requestContext);
        return cookieToken.isPresent() ? cookieToken : Optional.absent();
    }

    private Optional<String> getTokenFromCustomHeader(MultivaluedMap<String, String> headers) {
        final String header = headers.getFirst(customHeader);
        if (!Strings.isNullOrEmpty(header)) {
        	return  Optional.of(header);
        }

        return Optional.absent();
    } 
    
    private Optional<String> getTokenFromHeader(MultivaluedMap<String, String> headers) {
        final String header = headers.getFirst(AUTHORIZATION);
        if (header != null) {
            int space = header.indexOf(' ');
            if (space > 0) {
                final String method = header.substring(0, space);
                if (prefix.equalsIgnoreCase(method)) {
                    final String rawToken = header.substring(space + 1);
                    return Optional.of(rawToken);
                }
            }
        }

        return Optional.absent();
    }

    private Optional<String> getTokenFromCookie(ContainerRequestContext requestContext) {
        final Map<String, Cookie> cookies = requestContext.getCookies();

        if (cookieName != null && cookies.containsKey(cookieName)) {
            final Cookie tokenCookie = cookies.get(cookieName);
            final String rawToken = tokenCookie.getValue();
            return Optional.of(rawToken);
        }

        return Optional.absent();
    }

    /**
     * Builder for {@link JwtAuthFilter}.
     * <p>An {@link Authenticator} must be provided during the building process.</p>
     *
     * @param <P> the principal
     */
    public static class Builder<P extends Principal> extends AuthFilterBuilder<JWTClaimsSet, P, JwtAuthFilter<P>> {

        private ConfigurableJWTProcessor consumer;
        private String cookieName;
        private String header;

        public Builder<P> setJwtConsumer(ConfigurableJWTProcessor consumer) {
            this.consumer = consumer;
            return this;
        }

        public Builder<P> setCookieName(String cookieName) {
            this.cookieName = cookieName;
            return this;
        }
        
        public Builder<P> setAuthorizationHeader(String header){
        	this.header = header;
        	return this;
        }

        @Override
        protected JwtAuthFilter<P> newInstance() {
            checkNotNull(consumer, "ConfigurableJWTProcessor is not set");
            return new JwtAuthFilter<>(consumer, cookieName, header);
        }
    }
}
