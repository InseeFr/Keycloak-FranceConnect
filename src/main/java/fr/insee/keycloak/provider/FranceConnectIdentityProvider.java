package fr.insee.keycloak.provider;

import org.keycloak.broker.oidc.OIDCIdentityProvider;
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.crypto.HMACProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.services.ErrorPage;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.AuthenticationManager.AuthResult;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.resources.IdentityBrokerService;
import org.keycloak.services.resources.RealmsResource;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;

public class FranceConnectIdentityProvider extends OIDCIdentityProvider implements SocialIdentityProvider<OIDCIdentityProviderConfig> {

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
        @Path("logout_response")
        public Response logoutResponse(@QueryParam("state") String state) {
            UserSessionModel userSession;

            if (state == null) {
                logger.error("State not found in query string");

                if (!config.isIgnoreAbsentStateParameterLogout()) {
                    sendUserSessionNotFoundEvent();
                    return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
                }

                logger.warn("Using usersession from cookie");

                AuthResult authResult = AuthenticationManager.authenticateIdentityCookie(session, realm, false);
                if (authResult == null) {
                    return noValidUserSession();
                }

                userSession = authResult.getSession();
            } else {
                userSession = session.sessions().getUserSession(realm, state);

                if (userSession == null) {
                    return noValidUserSession();
                } else if (userSession.getState() != UserSessionModel.State.LOGGING_OUT) {
                    logger.error("Usersession in different state");
                    sendUserSessionNotFoundEvent();

                    return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, Messages.SESSION_NOT_ACTIVE);
                }
            }

            return AuthenticationManager.finishBrowserLogout(session, realm, userSession, session.getContext().getUri(), clientConnection, headers);
        }

        private Response noValidUserSession() {
            logger.error("No valid user session");
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
