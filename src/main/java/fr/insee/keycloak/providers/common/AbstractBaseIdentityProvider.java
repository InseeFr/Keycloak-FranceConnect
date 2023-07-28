package fr.insee.keycloak.providers.common;

import static fr.insee.keycloak.providers.common.Utils.transcodeSignatureToDER;
import static org.keycloak.util.JWKSUtils.getKeyWrappersForUse;

import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Optional;

import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.oidc.OIDCIdentityProvider;
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.crypto.JavaAlgorithm;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.jose.jwk.JSONWebKeySet;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jws.Algorithm;
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

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import jakarta.ws.rs.core.UriInfo;

public abstract class AbstractBaseIdentityProvider<T extends AbstractBaseProviderConfig>
    extends OIDCIdentityProvider implements SocialIdentityProvider<OIDCIdentityProviderConfig> {

  protected static final String ACR_CLAIM_NAME = "acr";

  protected JSONWebKeySet jwks;

  protected AbstractBaseIdentityProvider(KeycloakSession session, T config, JSONWebKeySet jwks) {
    super(session, config);
    this.jwks = jwks;
  }

  @Override
  public T getConfig() {
    return (T) super.getConfig();
  }

  @Override
  public Object callback(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {
    return new OIDCEndpoint(callback, realm, event, this ,getConfig());
  }

  @Override
  public Response keycloakInitiatedBrowserLogout(
      KeycloakSession session, UserSessionModel userSession, UriInfo uriInfo, RealmModel realm) {

    var config = getConfig();

    var logoutUrl = config.getLogoutUrl();
    if (logoutUrl == null || logoutUrl.trim().equals("")) {
      return null;
    }

    var idToken = getIdTokenForLogout(userSession);

    if (idToken != null && config.isBackchannelSupported()) {
      backchannelLogout(userSession, idToken);
      return null;
    }

    var sessionId = userSession.getId();
    var logoutUri = UriBuilder.fromUri(logoutUrl).queryParam("state", sessionId);

    if (idToken != null) {
      logoutUri.queryParam("id_token_hint", idToken);
    }
    var redirectUri =
        RealmsResource.brokerUrl(uriInfo)
            .path(IdentityBrokerService.class, "getEndpoint")
            .path(OIDCEndpoint.class, "logoutResponse")
            .build(realm.getName(), config.getAlias())
            .toString();

    logoutUri.queryParam("post_logout_redirect_uri", redirectUri);

    return Response.status(Response.Status.FOUND).location(logoutUri.build()).build();
  }

  protected String getIdTokenForLogout(UserSessionModel userSession) {
    return userSession.getNote(FEDERATED_ID_TOKEN);
  }

  @Override
  protected boolean verify(JWSInput jws) {
    logger.info("Validating: " + jws.getWireString());

    var config = getConfig();

    if (!config.isValidateSignature()) {
      return true;
    }

    if (Algorithm.HS256.equals(jws.getHeader().getAlgorithm())) {
      try (var vaultStringSecret = session.vault().getStringSecret(getConfig().getClientSecret())) {
        var clientSecret = vaultStringSecret.get().orElse(getConfig().getClientSecret());
        return HMACProvider.verify(jws, clientSecret.getBytes());
      }
    }

    try {
      var publicKey =
          Optional.ofNullable(getKeyWrappersForUse(jwks, JWK.Use.SIG).getKeyByKidAndAlg(jws.getHeader().getKeyId(),jws.getHeader().getAlgorithm().name()))
              .or(
                  () -> {
                    // Try reloading jwks url
                    jwks = Utils.getJsonWebKeySetFrom(config.getJwksUrl(), session);
                    return Optional.ofNullable(
                        getKeyWrappersForUse(jwks, JWK.Use.SIG).getKeyByKidAndAlg(jws.getHeader().getKeyId(),jws.getHeader().getAlgorithm().name()));
                  })
              .orElse(null);

      if (publicKey == null) {
        logger.error("No keys found for kid: " + jws.getHeader().getKeyId());
        return false;
      }

      var algorithm = JavaAlgorithm.getJavaAlgorithm(jws.getHeader().getAlgorithm().name());

      var verifier = Signature.getInstance(algorithm);
      verifier.initVerify((PublicKey) publicKey.getPublicKey());
      verifier.update(jws.getEncodedSignatureInput().getBytes(StandardCharsets.UTF_8));

      var signature = jws.getSignature();
      if (algorithm.endsWith("ECDSA")) {
        signature = transcodeSignatureToDER(signature);
      }

      return verifier.verify(signature);
    } catch (Exception ex) {
      logger.error("Signature verification failed", ex);
      return false;
    }
  }

  @Override
  public BrokeredIdentityContext getFederatedIdentity(String response) {

    try {
      var federatedIdentity = super.getFederatedIdentity(response);

      var idToken = (JsonWebToken) federatedIdentity.getContextData().get(VALIDATED_ID_TOKEN);
      var acrClaim = (String) idToken.getOtherClaims().get(ACR_CLAIM_NAME);

      var fcReturnedEidasLevel = EidasLevel.getOrDefault(acrClaim, null);
      var expectedEidasLevel = getConfig().getEidasLevel();

      if (fcReturnedEidasLevel == null) {
        throw new IdentityBrokerException("The returned eIDAS level cannot be retrieved");
      }

      logger.debugv(
          "Expecting eIDAS level: {0}, actual: {1}", expectedEidasLevel, fcReturnedEidasLevel);

      if (fcReturnedEidasLevel.compareTo(expectedEidasLevel) < 0) {
        throw new IdentityBrokerException("The returned eIDAS level is insufficient");
      }

      return federatedIdentity;

    } catch (IdentityBrokerException ex) {
      logger.error("Got response " + response);
      throw ex;
    }
  }

  protected class OIDCEndpoint extends Endpoint {

    private final T config;

    public OIDCEndpoint(
        AuthenticationCallback callback, RealmModel realm, EventBuilder event, AbstractOAuth2IdentityProvider provider, T config) {
      super(callback, realm, event, provider);
      this.config = config;
    }

    @GET
    @Path("logout_response")
    public Response logoutResponse(@QueryParam("state") String state) {

      if (state == null && config.isIgnoreAbsentStateParameterLogout()) {
        logger.warn("using usersession from cookie");
        var authResult = AuthenticationManager.authenticateIdentityCookie(session, realm, false);
        if (authResult == null) {
          return noValidUserSession();
        }

        var userSession = authResult.getSession();
        return AuthenticationManager.finishBrowserLogout(
            session, realm, userSession, session.getContext().getUri(), clientConnection, headers);
      } else if (state == null) {
        logger.error("no state parameter returned");
        sendUserSessionNotFoundEvent();

        return ErrorPage.error(
            session,
            null,
            Response.Status.BAD_REQUEST,
            Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
      }

      var userSession = session.sessions().getUserSession(realm, state);
      if (userSession == null) {
        return noValidUserSession();
      } else if (userSession.getState() != UserSessionModel.State.LOGGING_OUT) {
        logger.error("usersession in different state");
        sendUserSessionNotFoundEvent();
        return ErrorPage.error(
            session, null, Response.Status.BAD_REQUEST, Messages.SESSION_NOT_ACTIVE);
      }

      return AuthenticationManager.finishBrowserLogout(
          session, realm, userSession, session.getContext().getUri(), clientConnection, headers);
    }

    private Response noValidUserSession() {
      logger.error("no valid user session");
      sendUserSessionNotFoundEvent();

      return ErrorPage.error(
          session, null, Response.Status.BAD_REQUEST, Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
    }

    private void sendUserSessionNotFoundEvent() {
      var event = new EventBuilder(realm, session, clientConnection);
      event.event(EventType.LOGOUT);
      event.error(Errors.USER_SESSION_NOT_FOUND);
    }
  }
}
