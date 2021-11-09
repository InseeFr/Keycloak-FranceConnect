package fr.insee.keycloak.providers.utils;

import org.jboss.logging.Logger;
import org.keycloak.jose.jwk.JSONWebKeySet;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.utils.JWKSHttpUtils;

import java.io.IOException;

public final class JWKSUtils {

    private static final Logger logger = Logger.getLogger(JWKSUtils.class);

    private JWKSUtils() {}

    public static JSONWebKeySet getJsonWebKeySetFrom(String jwksUrl, KeycloakSession session) {
        try {
            return JWKSHttpUtils.sendJwksRequest(session, jwksUrl);
        } catch (IOException ex) {
            logger.warn("Error when fetching keys on JWKS URL: " + jwksUrl, ex);
            throw new IllegalStateException(ex);
        }
    }
}
