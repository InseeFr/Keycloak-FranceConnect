package fr.insee.keycloak.providers.agentconnect;

import fr.insee.keycloak.providers.agentconnect.AgentConnectIdentityProviderConfig.EidasLevel;
import fr.insee.keycloak.providers.utils.JWKSUtils;
import org.keycloak.broker.oidc.OIDCIdentityProvider;
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.crypto.JavaAlgorithm;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.jose.jwk.JSONWebKeySet;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKParser;
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

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.Signature;
import java.util.HashMap;
import java.util.Map;

import static fr.insee.keycloak.providers.utils.SignatureUtils.transcodeSignatureToDER;

public class AgentConnectIdentityProvider extends OIDCIdentityProvider
    implements SocialIdentityProvider<OIDCIdentityProviderConfig> {

  private static final String ACR_CLAIM_NAME = "acr";

  private JSONWebKeySet jwks;

  public AgentConnectIdentityProvider(KeycloakSession session, AgentConnectIdentityProviderConfig config) {
    super(session, config);
    jwks = JWKSUtils.getJsonWebKeySetFrom(config.getJwksUrl(), session);
  }

  @Override
  public Object callback(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {
    return new OIDCEndpoint(callback, realm, event, getAgentConnectConfig());
  }

  @Override
  protected UriBuilder createAuthorizationUrl(AuthenticationRequest request) {

    var config = getAgentConnectConfig();

    var uriBuilder = super.createAuthorizationUrl(request).queryParam("acr_values", config.getEidasLevel());

    logger.debugv("AgentConnect Authorization Url: {0}", uriBuilder.build().toString());

    return uriBuilder;
  }

  @Override
  public Response keycloakInitiatedBrowserLogout(KeycloakSession session, UserSessionModel userSession, UriInfo uriInfo,
      RealmModel realm) {

    var config = getAgentConnectConfig();

    var logoutUrl = config.getLogoutUrl();
    if (logoutUrl == null || logoutUrl.trim().equals("")) {
      return null;
    }

    var idToken = userSession.getNote(FEDERATED_ID_TOKEN);
    if (idToken != null && config.isBackchannelSupported()) {
      backchannelLogout(userSession, idToken);
      return null;
    }

    var sessionId = userSession.getId();
    var logoutUri = UriBuilder.fromUri(logoutUrl).queryParam("state", sessionId);

    if (idToken != null) {
      logoutUri.queryParam("id_token_hint", idToken);
    }
    var redirectUri = RealmsResource.brokerUrl(uriInfo).path(IdentityBrokerService.class, "getEndpoint")
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
    logger.info("Validating: " + jws.getWireString());

    var config = getAgentConnectConfig();

    if (!config.isValidateSignature()) {
      return true;
    }
    if (jws.getHeader().getAlgorithm() == Algorithm.HS256) {
      try (var vaultStringSecret = session.vault().getStringSecret(getConfig().getClientSecret())) {
        var clientSecret = vaultStringSecret.get().orElse(getConfig().getClientSecret());
        return HMACProvider.verify(jws, clientSecret.getBytes());
      }
    } else {
      try {
        var publicKey = getKeysForUse(jwks, JWK.Use.SIG).get(jws.getHeader().getKeyId());
        if (publicKey == null) {
          // Try reloading jwks url
          jwks = JWKSUtils.getJsonWebKeySetFrom(config.getJwksUrl(), session);
          publicKey = getKeysForUse(jwks, JWK.Use.SIG).get(jws.getHeader().getKeyId());
        }
        if (publicKey != null) {
          var algorithm = JavaAlgorithm.getJavaAlgorithm(jws.getHeader().getAlgorithm().name());

          var verifier = Signature.getInstance(algorithm);
          verifier.initVerify(publicKey);
          verifier.update(jws.getEncodedSignatureInput().getBytes(StandardCharsets.UTF_8));

          if (algorithm.endsWith("ECDSA")) {
            return verifier.verify(transcodeSignatureToDER(jws.getSignature()));
          } else {
            return verifier.verify(jws.getSignature());
          }
        } else {
          logger.error("No keys found for kid: " + jws.getHeader().getKeyId());
          return false;
        }
      } catch (Exception e) {
        logger.error("Signature verification failed", e);
        return false;
      }

    }

  }

  @Override
  public BrokeredIdentityContext getFederatedIdentity(String response) {

    try {
      var federatedIdentity = super.getFederatedIdentity(response);

      var idToken = (JsonWebToken) federatedIdentity.getContextData().get(VALIDATED_ID_TOKEN);
      var acrClaim = (String) idToken.getOtherClaims().get(ACR_CLAIM_NAME);

      var fcReturnedEidasLevel = EidasLevel.getOrDefault(acrClaim, null);
      var expectedEidasLevel = getAgentConnectConfig().getEidasLevel();

      if (fcReturnedEidasLevel == null) {
        throw new IdentityBrokerException("The returned eIDAS level cannot be retrieved");
      }

      logger.debugv("Expecting eIDAS level: {0}, actual: {1}", expectedEidasLevel, fcReturnedEidasLevel);

      if (fcReturnedEidasLevel.compareTo(expectedEidasLevel) < 0) {
        throw new IdentityBrokerException("The returned eIDAS level is insufficient");
      }

      return federatedIdentity;

    } catch (IdentityBrokerException ex) {
      logger.error("Got response " + response);
      throw ex;
    }
  }

  public AgentConnectIdentityProviderConfig getAgentConnectConfig() {
    return (AgentConnectIdentityProviderConfig) super.getConfig();
  }

  protected class OIDCEndpoint extends Endpoint {

    private final AgentConnectIdentityProviderConfig config;

    public OIDCEndpoint(AuthenticationCallback callback, RealmModel realm, EventBuilder event,
        AgentConnectIdentityProviderConfig config) {
      super(callback, realm, event);
      this.config = config;
    }

    @GET
    @Path("logout_response")
    public Response logoutResponse(@QueryParam("state") String state) {

      if (state == null && config.isIgnoreAbsentStateParameterLogout()) {
        logger.warn("using usersession from cookie");
        var authResult = AuthenticationManager.authenticateIdentityCookie(session, realm,
            false);
        if (authResult == null) {
          return noValidUserSession();
        }

        var userSession = authResult.getSession();
        return AuthenticationManager.finishBrowserLogout(session, realm, userSession, session.getContext().getUri(),
            clientConnection, headers);
      } else if (state == null) {
        logger.error("no state parameter returned");
        sendUserSessionNotFoundEvent();

        return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
      }

      var userSession = session.sessions().getUserSession(realm, state);
      if (userSession == null) {
        return noValidUserSession();
      } else if (userSession.getState() != UserSessionModel.State.LOGGING_OUT) {
        logger.error("usersession in different state");
        sendUserSessionNotFoundEvent();
        return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, Messages.SESSION_NOT_ACTIVE);
      }

      return AuthenticationManager.finishBrowserLogout(session, realm, userSession, session.getContext().getUri(),
          clientConnection, headers);
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

  // Agent connect doesn't publish an usage for the rsa key (even though it is not
  // used)
  public static Map<String, PublicKey> getKeysForUse(JSONWebKeySet keySet, JWK.Use requestedUse) {
    Map<String, PublicKey> result = new HashMap<>();

    for (var jwk : keySet.getKeys()) {
      var parser = JWKParser.create(jwk);
      logger.info("Parsing " + jwk.getKeyId());
      if (jwk.getPublicKeyUse() != null && jwk.getPublicKeyUse().equals(requestedUse.asString())
          && parser.isKeyTypeSupported(jwk.getKeyType())) {
        result.put(jwk.getKeyId(), parser.toPublicKey());
      }
    }

    return result;
  }
}
