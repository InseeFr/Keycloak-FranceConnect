package fr.insee.keycloak.providers.franceconnect;

import com.fasterxml.jackson.databind.JsonNode;
import fr.insee.keycloak.providers.common.EidasLevel;
import fr.insee.keycloak.providers.common.Utils;
import org.jboss.logging.Logger;
import org.keycloak.broker.oidc.OIDCIdentityProvider;
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.crypto.JavaAlgorithm;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.jose.jwe.JWE;
import org.keycloak.jose.jwe.JWEException;
import org.keycloak.jose.jwk.JSONWebKeySet;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jws.Algorithm;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.jose.jws.crypto.HMACProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.utils.JWKSHttpUtils;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.IDToken;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.services.ErrorPage;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.resources.IdentityBrokerService;
import org.keycloak.services.resources.RealmsResource;
import org.keycloak.util.JsonSerialization;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.*;
import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Signature;

import static org.keycloak.util.JWKSUtils.getKeysForUse;

public class FranceConnectIdentityProvider extends OIDCIdentityProvider
    implements SocialIdentityProvider<OIDCIdentityProviderConfig> {

  private static final Logger logger = Logger.getLogger(FranceConnectIdentityProvider.class);

  private static final String ACR_CLAIM_NAME = "acr";
  private static final String BROKER_NONCE_PARAM = "BROKER_NONCE";
  private static final MediaType APPLICATION_JWT_TYPE = MediaType.valueOf("application/jwt");

  private JSONWebKeySet jwks;

  public FranceConnectIdentityProvider(KeycloakSession session, FranceConnectIdentityProviderConfig config) {
    super(session, config);

    if (!config.getEidasLevel().equals(EidasLevel.EIDAS1)) {
      jwks = Utils.getJsonWebKeySetFrom(config.getJwksUrl(), session);
    }
  }

  @Override
  public Object callback(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {
    return new OIDCEndpoint(callback, realm, event, getFranceConnectConfig());
  }

  private void initJwks(FranceConnectIdentityProviderConfig config) {
    try {
      jwks = JWKSHttpUtils.sendJwksRequest(session, config.getJwksUrl());
    } catch (IOException e) {
      logger.warn("Error when fetching keys on JWKS URL: " + config.getJwksUrl(), e);
    }
  }

  @Override
  public JsonWebToken validateToken(String encodedToken) {
    var ignoreAudience = false;
    switch (getFranceConnectConfig().getEidasLevel()) {
    case EIDAS1:
      return validateToken(encodedToken, ignoreAudience);
    case EIDAS2:
    case EIDAS3:
    default:
      return decryptAndValidateToken(encodedToken, ignoreAudience);
    }

  }

  private String decryptJwe(String encryptedJwe) throws JWEException {
    var jwe = new JWE(encryptedJwe);
    var kid = jwe.getHeader().getKeyId();

    // finding the key from all the realms keys
    var k = session.keys().getKeysStream(session.getContext().getRealm())
        .filter(key -> key.getKid().equalsIgnoreCase(kid)).findFirst().get().getPrivateKey();

    if (k != null) {
      logger.debug("Found corresponding secret key for kid " + kid);
    } else {
      throw new IdentityBrokerException("No key found for kid" + kid);
    }
    jwe.getKeyStorage().setDecryptionKey(k);

    return new String(jwe.verifyAndDecodeJwe().getContent());

  }

  private JsonWebToken decryptAndValidateToken(String encodedToken, boolean ignoreAudience) {

    try {
      var decryptedContent = decryptJwe(encodedToken);
      return validateToken(decryptedContent, ignoreAudience);
    } catch (JWEException e) {
      throw new IdentityBrokerException("Invalid token", e);
    }

  }

  /** France connect requires nonce to be exactly 64 char long, so...yes */
  @Override
  protected UriBuilder createAuthorizationUrl(AuthenticationRequest request) {
    var config = getFranceConnectConfig();

    var uriBuilder = super.createAuthorizationUrl(request);
    var nonce = DatatypeConverter.printHexBinary(KeycloakModelUtils.generateSecret(32));
    var authenticationSession = request.getAuthenticationSession();
    authenticationSession.setClientNote(BROKER_NONCE_PARAM, nonce);
    uriBuilder.replaceQueryParam(OIDCLoginProtocol.NONCE_PARAM, nonce);
    uriBuilder.queryParam("acr_values", config.getEidasLevel());
    return uriBuilder;
  }

  @Override
  public Response keycloakInitiatedBrowserLogout(KeycloakSession session, UserSessionModel userSession, UriInfo uriInfo,
      RealmModel realm) {

    var config = getFranceConnectConfig();

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
        .path(OIDCEndpoint.class, "logoutResponse").build(realm.getName(), config.getAlias()).toString();

    logoutUri.queryParam("post_logout_redirect_uri", redirectUri);

    return Response.status(Response.Status.FOUND).location(logoutUri.build()).build();
  }

  @Override
  protected boolean verify(JWSInput jws) {
    logger.info("Validating: " + jws.getWireString());

    var config = getFranceConnectConfig();

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
          initJwks(config);
          publicKey = getKeysForUse(jwks, JWK.Use.SIG).get(jws.getHeader().getKeyId());
        }
        if (publicKey != null) {

          var algorithm = JavaAlgorithm.getJavaAlgorithm(jws.getHeader().getAlgorithm().name());

          var verifier = Signature.getInstance(algorithm);
          verifier.initVerify(publicKey);
          verifier.update(jws.getEncodedSignatureInput().getBytes(StandardCharsets.UTF_8));

          if (algorithm.endsWith("ECDSA")) {
            return verifier.verify(Utils.transcodeSignatureToDER(jws.getSignature()));
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

  private SimpleHttp.Response executeRequest(String url, SimpleHttp request) throws IOException {
    var response = request.asResponse();
    if (response.getStatus() != 200) {
      var msg = "failed to invoke url [" + url + "]";
      try {
        var tmp = response.asString();
        if (tmp != null)
          msg = tmp;

      } catch (IOException e) {

      }
      throw new IdentityBrokerException("Failed to invoke url [" + url + "]: " + msg);
    }
    return response;
  }

  protected BrokeredIdentityContext extractIdentity(AccessTokenResponse tokenResponse, String accessToken,
      JsonWebToken idToken) throws IOException {
    var id = idToken.getSubject();
    var identity = new BrokeredIdentityContext(id);
    var name = (String) idToken.getOtherClaims().get(IDToken.NAME);
    var givenName = (String) idToken.getOtherClaims().get(IDToken.GIVEN_NAME);
    var familyName = (String) idToken.getOtherClaims().get(IDToken.FAMILY_NAME);
    var preferredUsername = (String) idToken.getOtherClaims().get(getusernameClaimNameForIdToken());
    var email = (String) idToken.getOtherClaims().get(IDToken.EMAIL);

    if (!getConfig().isDisableUserInfoService()) {
      var userInfoUrl = getUserInfoUrl();
      if (userInfoUrl != null && !userInfoUrl.isEmpty()) {

        if (accessToken != null) {
          var response = executeRequest(userInfoUrl,
              SimpleHttp.doGet(userInfoUrl, session).header("Authorization", "Bearer " + accessToken));
          var contentType = response.getFirstHeader(HttpHeaders.CONTENT_TYPE);
          MediaType contentMediaType;
          try {
            contentMediaType = MediaType.valueOf(contentType);
          } catch (IllegalArgumentException ex) {
            contentMediaType = null;
          }
          if (contentMediaType == null || contentMediaType.isWildcardSubtype() || contentMediaType.isWildcardType()) {
            throw new RuntimeException(
                "Unsupported content-type [" + contentType + "] in response from [" + userInfoUrl + "].");
          }
          JsonNode userInfo;

          if (MediaType.APPLICATION_JSON_TYPE.isCompatible(contentMediaType)) {
            userInfo = response.asJson();
          } else if (APPLICATION_JWT_TYPE.isCompatible(contentMediaType)) {
            switch (getFranceConnectConfig().getEidasLevel()) {
            case EIDAS1:
              try {
                userInfo = getJsonFromJWT(response.asString());
              } catch (IdentityBrokerException e) {
                throw new RuntimeException(
                    "Failed to verify signature of userinfo response from [" + userInfoUrl + "].", e);
              }
              break;
            case EIDAS2:
            case EIDAS3:
            default:
              try {
                String decryptedContent = decryptJwe(response.asString());
                try {
                  userInfo = getJsonFromJWT(decryptedContent);
                } catch (IdentityBrokerException e) {
                  throw new RuntimeException(
                      "Failed to verify signature of userinfo response from [" + userInfoUrl + "].", e);
                }
                break;
              } catch (JWEException e) {
                throw new IdentityBrokerException("Invalid token", e);
              }

            }
          } else {
            throw new RuntimeException(
                "Unsupported content-type [" + contentType + "] in response from [" + userInfoUrl + "].");
          }

          id = getJsonProperty(userInfo, "sub");
          name = getJsonProperty(userInfo, "name");
          givenName = getJsonProperty(userInfo, IDToken.GIVEN_NAME);
          familyName = getJsonProperty(userInfo, IDToken.FAMILY_NAME);
          preferredUsername = getUsernameFromUserInfo(userInfo);
          email = getJsonProperty(userInfo, "email");
          AbstractJsonUserAttributeMapper.storeUserProfileForMapper(identity, userInfo, getConfig().getAlias());
        }
      }
    }
    identity.getContextData().put(VALIDATED_ID_TOKEN, idToken);

    identity.setId(id);

    if (givenName != null) {
      identity.setFirstName(givenName);
    }

    if (familyName != null) {
      identity.setLastName(familyName);
    }

    if (givenName == null && familyName == null) {
      identity.setName(name);
    }

    identity.setEmail(email);

    identity.setBrokerUserId(getConfig().getAlias() + "." + id);

    if (preferredUsername == null) {
      preferredUsername = email;
    }

    if (preferredUsername == null) {
      preferredUsername = id;
    }

    identity.setUsername(preferredUsername);
    if (tokenResponse != null && tokenResponse.getSessionState() != null) {
      identity.setBrokerSessionId(getConfig().getAlias() + "." + tokenResponse.getSessionState());
    }
    if (tokenResponse != null)
      identity.getContextData().put(FEDERATED_ACCESS_TOKEN_RESPONSE, tokenResponse);
    if (tokenResponse != null)
      processAccessTokenResponse(identity, tokenResponse);

    return identity;
  }

  private JsonNode getJsonFromJWT(String jwt) throws IdentityBrokerException {
    JWSInput jwsInput;

    try {
      jwsInput = new JWSInput(jwt);
    } catch (JWSInputException cause) {
      throw new RuntimeException("Failed to parse JWT userinfo response", cause);
    }

    if (verify(jwsInput)) {
      try {
        return JsonSerialization.readValue(jwsInput.getContent(), JsonNode.class);
      } catch (IOException e) {
        throw new IdentityBrokerException("Failed to parse jwt", e);
      }
    } else {
      throw new IdentityBrokerException("Failed to verify signature of of jwt");
    }

  }

  @Override
  public BrokeredIdentityContext getFederatedIdentity(String response) {

    try {
      var federatedIdentity = super.getFederatedIdentity(response);

      var idToken = (JsonWebToken) federatedIdentity.getContextData().get(VALIDATED_ID_TOKEN);
      var acrClaim = (String) idToken.getOtherClaims().get(ACR_CLAIM_NAME);

      var fcReturnedEidasLevel = EidasLevel.getOrDefault(acrClaim, null);
      var expectedEidasLevel = getFranceConnectConfig().getEidasLevel();

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

  public FranceConnectIdentityProviderConfig getFranceConnectConfig() {
    return (FranceConnectIdentityProviderConfig) super.getConfig();
  }

  protected class OIDCEndpoint extends Endpoint {

    private final FranceConnectIdentityProviderConfig config;

    public OIDCEndpoint(AuthenticationCallback callback, RealmModel realm, EventBuilder event,
        FranceConnectIdentityProviderConfig config) {
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
      var event = new EventBuilder(realm, session, clientConnection);
      event.event(EventType.LOGOUT);
      event.error(Errors.USER_SESSION_NOT_FOUND);
    }
  }
}
