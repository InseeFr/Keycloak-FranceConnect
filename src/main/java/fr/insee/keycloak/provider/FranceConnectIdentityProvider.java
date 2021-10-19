package fr.insee.keycloak.provider;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.Signature;
import java.util.HashMap;
import java.util.Map;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;
import javax.xml.bind.DatatypeConverter;

import org.keycloak.broker.oidc.OIDCIdentityProvider;
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.common.util.Base64Url;
import org.keycloak.common.util.Time;
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
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.utils.JWKSHttpUtils;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.services.ErrorPage;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.resources.IdentityBrokerService;
import org.keycloak.services.resources.RealmsResource;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.util.TokenUtil;
import org.keycloak.vault.VaultStringSecret;

import fr.insee.keycloak.provider.FranceConnectIdentityProviderConfig.EidasLevel;

public class FranceConnectIdentityProvider extends OIDCIdentityProvider
    implements SocialIdentityProvider<OIDCIdentityProviderConfig> {

  private static final String ACR_CLAIM_NAME = "acr";

  private static JSONWebKeySet jwks;

  private static final String BROKER_NONCE_PARAM = "BROKER_NONCE";

  public FranceConnectIdentityProvider(
      KeycloakSession session, FranceConnectIdentityProviderConfig config) {
    super(session, config);
    initjwks(config);
  }

  @Override
  public Object callback(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {
    return new OIDCEndpoint(callback, realm, event, getFranceConnectConfig());
  }

  private void initjwks(FranceConnectIdentityProviderConfig config) {
    try {
      jwks = JWKSHttpUtils.sendJwksRequest(session, config.getJwksUrl());
    } catch (IOException e) {
      logger.warn("Error when fetching keys on JWKS URL: " + config.getJwksUrl(), e);
    }
  }


  /** France connect requires nonce to be exactly 64 char long, so...yes */
  @Override
  protected UriBuilder createAuthorizationUrl(AuthenticationRequest request) {
    FranceConnectIdentityProviderConfig config = getFranceConnectConfig();

    UriBuilder uriBuilder = super.createAuthorizationUrl(request);
    String nonce = DatatypeConverter.printHexBinary(KeycloakModelUtils.generateSecret(32));
    AuthenticationSessionModel authenticationSession = request.getAuthenticationSession();
    authenticationSession.setClientNote(BROKER_NONCE_PARAM, nonce);
    uriBuilder.replaceQueryParam(OIDCLoginProtocol.NONCE_PARAM, nonce);
    uriBuilder.queryParam("acr_values", config.getEidasLevel());
    return uriBuilder;
  }

  
  
  @Override
  public Response keycloakInitiatedBrowserLogout(
      KeycloakSession session, UserSessionModel userSession, UriInfo uriInfo, RealmModel realm) {

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
    UriBuilder logoutUri = UriBuilder.fromUri(logoutUrl).queryParam("state", sessionId);

    if (idToken != null) {
      logoutUri.queryParam("id_token_hint", idToken);
    }
    String redirectUri =
        RealmsResource.brokerUrl(uriInfo)
            .path(IdentityBrokerService.class, "getEndpoint")
            .path(OIDCEndpoint.class, "logoutResponse")
            .build(realm.getName(), config.getAlias())
            .toString();

    logoutUri.queryParam("post_logout_redirect_uri", redirectUri);

    return Response.status(Response.Status.FOUND).location(logoutUri.build()).build();
  }

  @Override
  protected boolean verify(JWSInput jws) {
    logger.info("Validating: " + jws.getWireString());

    FranceConnectIdentityProviderConfig config = getFranceConnectConfig();

    if (!config.isValidateSignature()) {
      return true;
    }
    if (jws.getHeader().getAlgorithm() == Algorithm.HS256) {
      try (VaultStringSecret vaultStringSecret =
          session.vault().getStringSecret(getConfig().getClientSecret())) {
        String clientSecret = vaultStringSecret.get().orElse(getConfig().getClientSecret());
        return HMACProvider.verify(jws, clientSecret.getBytes());
      }
    } else {
      try {

        PublicKey publicKey = getKeysForUse(jwks, JWK.Use.SIG).get(jws.getHeader().getKeyId());
        if (publicKey == null) {
          // Try reloading jwks url
          initjwks(config);
          publicKey = getKeysForUse(jwks, JWK.Use.SIG).get(jws.getHeader().getKeyId());
        }
        if (publicKey != null) {

          Signature verifier;

          String algorithm = JavaAlgorithm.getJavaAlgorithm(jws.getHeader().getAlgorithm().name());

          verifier = Signature.getInstance(algorithm);
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
      BrokeredIdentityContext federatedIdentity = super.getFederatedIdentity(response);

      JsonWebToken idToken =
          (JsonWebToken) federatedIdentity.getContextData().get(VALIDATED_ID_TOKEN);
      String acrClaim = (String) idToken.getOtherClaims().get(ACR_CLAIM_NAME);

      EidasLevel fcReturnedEidasLevel = EidasLevel.getOrDefault(acrClaim, null);
      EidasLevel expectedEidasLevel = getFranceConnectConfig().getEidasLevel();

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

  public FranceConnectIdentityProviderConfig getFranceConnectConfig() {
    return (FranceConnectIdentityProviderConfig) super.getConfig();
  }

  protected class OIDCEndpoint extends Endpoint {

    private final FranceConnectIdentityProviderConfig config;

    public OIDCEndpoint(
        AuthenticationCallback callback,
        RealmModel realm,
        EventBuilder event,
        FranceConnectIdentityProviderConfig config) {
      super(callback, realm, event);
      this.config = config;
    }

    @GET
    @Path("logout_response")
    public Response logoutResponse(@QueryParam("state") String state) {

      if (state == null && config.isIgnoreAbsentStateParameterLogout()) {
        logger.warn("using usersession from cookie");
        AuthenticationManager.AuthResult authResult =
            AuthenticationManager.authenticateIdentityCookie(session, realm, false);
        if (authResult == null) {
          return noValidUserSession();
        }

        UserSessionModel userSession = authResult.getSession();
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

      UserSessionModel userSession = session.sessions().getUserSession(realm, state);
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
      EventBuilder event = new EventBuilder(realm, session, clientConnection);
      event.event(EventType.LOGOUT);
      event.error(Errors.USER_SESSION_NOT_FOUND);
    }
  }

  // Agent connect doesn't publish an usage for the rsa key (even though it is not
  // used)
  public static Map<String, PublicKey> getKeysForUse(JSONWebKeySet keySet, JWK.Use requestedUse) {
    Map<String, PublicKey> result = new HashMap<>();

    for (JWK jwk : keySet.getKeys()) {
      JWKParser parser = JWKParser.create(jwk);
      logger.info("Parsing " + jwk.getKeyId());
      if (jwk.getPublicKeyUse() != null
          && jwk.getPublicKeyUse().equals(requestedUse.asString())
          && parser.isKeyTypeSupported(jwk.getKeyType())) {
        result.put(jwk.getKeyId(), parser.toPublicKey());
      }
    }

    return result;
  }

  // We need this due to a bug in signature verification
  // (https://github.com/GluuFederation/oxAuth/issues/1210)
  public static byte[] transcodeSignatureToDER(byte[] jwsSignature) {
    // Adapted from
    // org.apache.xml.security.algorithms.implementations.SignatureECDSA
    int rawLen = jwsSignature.length / 2;
    int i;
    for (i = rawLen; (i > 0) && (jwsSignature[rawLen - i] == 0); i--) {
      // do nothing
    }
    int j = i;
    if (jwsSignature[rawLen - i] < 0) {
      j += 1;
    }
    int k;
    for (k = rawLen; (k > 0) && (jwsSignature[2 * rawLen - k] == 0); k--) {
      // do nothing
    }
    int l = k;
    if (jwsSignature[2 * rawLen - k] < 0) {
      l += 1;
    }
    int len = 2 + j + 2 + l;
    if (len > 255) {
      throw new RuntimeException("Invalid ECDSA signature format");
    }
    int offset;
    final byte derSignature[];
    if (len < 128) {
      derSignature = new byte[2 + 2 + j + 2 + l];
      offset = 1;
    } else {
      derSignature = new byte[3 + 2 + j + 2 + l];
      derSignature[1] = (byte) 0x81;
      offset = 2;
    }
    derSignature[0] = 48;
    derSignature[offset++] = (byte) len;
    derSignature[offset++] = 2;
    derSignature[offset++] = (byte) j;
    System.arraycopy(jwsSignature, rawLen - i, derSignature, (offset + j) - i, i);
    offset += j;
    derSignature[offset++] = 2;
    derSignature[offset++] = (byte) l;
    System.arraycopy(jwsSignature, 2 * rawLen - k, derSignature, (offset + l) - k, k);
    return derSignature;
  }
}
