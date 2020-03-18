package fr.insee.keycloak.provider;

import org.keycloak.OAuth2Constants;
import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.oidc.OIDCIdentityProvider;
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.crypto.HMACProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.services.ErrorPage;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.resources.IdentityBrokerService;
import org.keycloak.services.resources.RealmsResource;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.QueryParam;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class FranceConnectIdentityProvider extends OIDCIdentityProvider implements SocialIdentityProvider<OIDCIdentityProviderConfig> {

    private static final Pattern EIDAS_PATTERN = Pattern.compile("eidas(\\d+)");
    private static final String ACR_INSUFFICIENT_MESSAGE = "acrInsufficientMessage";

    public FranceConnectIdentityProvider(KeycloakSession session, FranceConnectIdentityProviderConfig config) {
        super(session, config);
    }

    @Override
    public Object callback(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {
        return new OIDCEndpoint(callback, realm, event, getFranceConnectConfig());
    }

    @Override
    protected UriBuilder createAuthorizationUrl(AuthenticationRequest request) {

        FranceConnectIdentityProviderConfig config = getFranceConnectConfig();

        UriBuilder uriBuilder = super.createAuthorizationUrl(request)
                .queryParam("acr_values", config.getEidasLevel());

        logger.debug("FranceConnect Authorization Url: " + uriBuilder.build().toString());

        return uriBuilder;
    }

    @Override
    public Response keycloakInitiatedBrowserLogout(KeycloakSession session, UserSessionModel userSession,
                                                   UriInfo uriInfo, RealmModel realm) {

        FranceConnectIdentityProviderConfig config = getFranceConnectConfig();

        String logoutUrl = config.getLogoutUrl();
        if (logoutUrl == null || logoutUrl.trim().equals("")) {
            return null;
        }

        String idToken = userSession.getNote(FEDERATED_ID_TOKEN);
        if (idToken != null && config.isBackchannelSupported()) {
            backchannelLogout(userSession, idToken);
            return null;
        }

        String sessionId = userSession.getId();
        UriBuilder logoutUri = UriBuilder.fromUri(logoutUrl)
                .queryParam("state", sessionId);

        if (idToken != null) {
            logoutUri.queryParam("id_token_hint", idToken);
        }
        String redirectUri = RealmsResource.brokerUrl(uriInfo)
            .path(IdentityBrokerService.class, "getEndpoint")
            .path(OIDCEndpoint.class, "logoutResponse")
            .build(realm.getName(), config.getAlias())
            .toString();

        logoutUri.queryParam("post_logout_redirect_uri", redirectUri);

        return Response.status(Response.Status.FOUND)
            .location(logoutUri.build())
            .build();
    }

    @Override
    protected boolean verify(JWSInput jws) {

        FranceConnectIdentityProviderConfig config = getFranceConnectConfig();

        if (!config.isValidateSignature()) {
            return true;
        }

        return HMACProvider.verify(jws, config.getClientSecret().getBytes());
    }

    @Override
    public BrokeredIdentityContext getFederatedIdentity(String response) {
        try {
            return super.getFederatedIdentity(response);
        } catch (IdentityBrokerException e) {
            logger.error("Got response " + response);
            throw e;
        }
    }

    public FranceConnectIdentityProviderConfig getFranceConnectConfig() {
        return (FranceConnectIdentityProviderConfig) super.getConfig();
    }

    protected class OIDCEndpoint extends Endpoint {

        private final FranceConnectIdentityProviderConfig config;

        public OIDCEndpoint(AuthenticationCallback callback, RealmModel realm,
                            EventBuilder event, FranceConnectIdentityProviderConfig config) {
            super(callback, realm, event);
            this.config = config;
        }

        @GET
        public Response authResponse(@QueryParam(AbstractOAuth2IdentityProvider.OAUTH2_PARAMETER_STATE) String state,
                                     @QueryParam(AbstractOAuth2IdentityProvider.OAUTH2_PARAMETER_CODE) String authorizationCode,
                                     @QueryParam(OAuth2Constants.ERROR) String error) {
            if (error != null) {
                //logger.error("Failed " + getConfig().getAlias() + " broker login: " + error);
                if (error.equals(ACCESS_DENIED)) {
                    logger.error(ACCESS_DENIED + " for broker login " + getConfig().getProviderId());
                    return callback.cancelled(state);
                } else {
                    logger.error(error + " for broker login " + getConfig().getProviderId());
                    return callback.error(state, Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
                }
            }

            try {
                if (authorizationCode != null) {
                    String response = generateTokenRequest(authorizationCode).asString();
                    BrokeredIdentityContext federatedIdentity = getFederatedIdentity(response);

                    // Code to add verification for eidas level
                    // See: https://github.com/InseeFr/Keycloak-FranceConnect/issues/29
                    JsonWebToken idToken = (JsonWebToken) federatedIdentity.getContextData().get("VALIDATED_ID_TOKEN");
                    if (idToken == null) {
                        event.event(EventType.LOGIN);
                        event.error(Errors.INVALID_TOKEN);
                        return ErrorPage.error(session, null, Response.Status.BAD_GATEWAY, Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
                    }
                    String acrReturned = (String) idToken.getOtherClaims().get("acr");
                    String acrRequested = this.config.getEidasLevel().toString();
                    if (acrReturned == null || acrRequested == null) {
                        event.event(EventType.LOGIN);
                        event.error(Errors.INVALID_TOKEN);
                        return ErrorPage.error(session, null, Response.Status.BAD_GATEWAY, Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
                    }
                    Matcher acrReturnedMatcher = EIDAS_PATTERN.matcher(acrReturned);
                    Matcher acrRequestedMatcher = EIDAS_PATTERN.matcher(acrRequested);
                    if (!acrReturnedMatcher.find() || !acrRequestedMatcher.find()) {
                        event.event(EventType.LOGIN);
                        event.error(Errors.INVALID_TOKEN);
                        return ErrorPage.error(session, null, Response.Status.BAD_GATEWAY, Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
                    }
                    int acrReturnedInt = Integer.decode(acrReturnedMatcher.group(1));
                    int acrRequestInt = Integer.decode(acrRequestedMatcher.group(1));
                    logger.debugv("FranceConnect acrReturned={0} vs acrRequest={1}", acrReturnedInt, acrRequestInt);
                    if (acrReturnedInt < acrRequestInt) {
                        event.event(EventType.LOGIN);
                        event.error(Errors.INVALID_TOKEN);
                        return ErrorPage.error(session, null, Response.Status.BAD_GATEWAY, ACR_INSUFFICIENT_MESSAGE);
                    }
                    // End verification for eidas level

                    if (getConfig().isStoreToken()) {
                        // make sure that token wasn't already set by getFederatedIdentity();
                        // want to be able to allow provider to set the token itself.
                        if (federatedIdentity.getToken() == null) federatedIdentity.setToken(response);
                    }

                    federatedIdentity.setIdpConfig(getConfig());
                    federatedIdentity.setIdp(FranceConnectIdentityProvider.this);
                    federatedIdentity.setCode(state);

                    return callback.authenticated(federatedIdentity);
                }
            } catch (WebApplicationException e) {
                return e.getResponse();
            } catch (Exception e) {
                logger.error("Failed to make identity provider oauth callback", e);
            }
            event.event(EventType.LOGIN);
            event.error(Errors.IDENTITY_PROVIDER_LOGIN_FAILURE);
            return ErrorPage.error(session, null, Response.Status.BAD_GATEWAY, Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
        }

        @GET
        @Path("logout_response")
        public Response logoutResponse(@QueryParam("state") String state) {

            if (state == null && config.isIgnoreAbsentStateParameterLogout()) {
                logger.warn("using usersession from cookie");
                AuthenticationManager.AuthResult authResult = AuthenticationManager.authenticateIdentityCookie(session, realm, false);
                if (authResult == null) {
                    return noValidUserSession();
                }

                UserSessionModel userSession = authResult.getSession();
                return AuthenticationManager.finishBrowserLogout(session, realm, userSession, session.getContext().getUri(), clientConnection, headers);
            } else if (state == null) {
                logger.error("no state parameter returned");
                sendUserSessionNotFoundEvent();

                return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
            }

            UserSessionModel userSession = session.sessions().getUserSession(realm, state);
            if (userSession == null) {
                return noValidUserSession();
            } else if (userSession.getState() != UserSessionModel.State.LOGGING_OUT) {
                logger.error("usersession in different state");
                sendUserSessionNotFoundEvent();
                return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, Messages.SESSION_NOT_ACTIVE);
            }

            return AuthenticationManager.finishBrowserLogout(session, realm, userSession, session.getContext().getUri(), clientConnection, headers);
        }

        private Response noValidUserSession() {
            logger.error("no valid user session");
            sendUserSessionNotFoundEvent();

            return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
        }

        private void sendUserSessionNotFoundEvent() {
            EventBuilder event = new EventBuilder(realm, session, clientConnection);
            event.event(EventType.LOGOUT);
            event.error(Errors.USER_SESSION_NOT_FOUND);
        }

    }

}
