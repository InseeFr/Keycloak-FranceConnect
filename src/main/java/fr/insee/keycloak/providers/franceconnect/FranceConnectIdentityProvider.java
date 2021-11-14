package fr.insee.keycloak.providers.franceconnect;

import com.fasterxml.jackson.databind.JsonNode;
import fr.insee.keycloak.providers.common.AbstractBaseIdentityProvider;
import fr.insee.keycloak.providers.common.Utils;
import org.keycloak.OAuth2Constants;
import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.jose.jwe.JWE;
import org.keycloak.jose.jwe.JWEException;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.IDToken;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.util.JsonSerialization;

import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.UriBuilder;
import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.util.Optional;

import static fr.insee.keycloak.providers.common.EidasLevel.EIDAS1;
import static javax.ws.rs.core.Response.Status.OK;

public class FranceConnectIdentityProvider extends AbstractBaseIdentityProvider<FranceConnectIdentityProviderConfig> {

  private static final String BROKER_NONCE_PARAM = "BROKER_NONCE";
  private static final MediaType APPLICATION_JWT_TYPE = MediaType.valueOf("application/jwt");

  public FranceConnectIdentityProvider(KeycloakSession session, FranceConnectIdentityProviderConfig config) {
    super(
        session, config,
        EIDAS1.equals(config.getEidasLevel()) ? null : Utils.getJsonWebKeySetFrom(config.getJwksUrl(), session)
    );
  }

  /**
   * France connect requires nonce to be exactly 64 char long, so...yes
   */
  @Override
  protected UriBuilder createAuthorizationUrl(AuthenticationRequest request) {
    var config = getConfig();
    var authenticationSession = request.getAuthenticationSession();

    authenticationSession.setClientNote(OAuth2Constants.ACR_VALUES, config.getEidasLevel().toString());
    var uriBuilder = super.createAuthorizationUrl(request);

    var nonce = DatatypeConverter.printHexBinary(KeycloakModelUtils.generateSecret(32));
    authenticationSession.setClientNote(BROKER_NONCE_PARAM, nonce);
    uriBuilder.replaceQueryParam(OIDCLoginProtocol.NONCE_PARAM, nonce);

    logger.debugv("FC Authorization Url: {0}", uriBuilder.build().toString());

    return uriBuilder;
  }

  @Override
  public JsonWebToken validateToken(String encodedToken) {
    var ignoreAudience = false;
    var eidasLevel = getConfig().getEidasLevel();

    var token = encodedToken;
    if (!EIDAS1.equals(eidasLevel)) {
      token = decryptJWE(encodedToken);
    }

    return validateToken(token, ignoreAudience);
  }

  @Override
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
            try {
              var eidasLevel = getConfig().getEidasLevel();
              var jwt = EIDAS1.equals(eidasLevel) ? response.asString() : decryptJWE(response.asString());
              userInfo = getJsonFromJWT(jwt);
            } catch (IdentityBrokerException ex) {
              throw new RuntimeException("Failed to verify signature of userinfo response from [" + userInfoUrl + "].", ex);
            }
          } else {
            throw new RuntimeException("Unsupported content-type [" + contentType + "] in response from [" + userInfoUrl + "].");
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

    identity.setId(id);
    identity.getContextData().put(VALIDATED_ID_TOKEN, idToken);

    identity.setFirstName(givenName);
    identity.setLastName(familyName);

    if (givenName == null && familyName == null) {
      identity.setName(name);
    }

    identity.setEmail(email);
    identity.setBrokerUserId(getConfig().getAlias() + "." + id);

    var emailOptional = Optional.ofNullable(email);
    preferredUsername = Optional.ofNullable(preferredUsername)
        .or(() -> emailOptional)
        .orElse(id);
    identity.setUsername(preferredUsername);

    if (tokenResponse != null && tokenResponse.getSessionState() != null) {
      identity.setBrokerSessionId(getConfig().getAlias() + "." + tokenResponse.getSessionState());
    }

    if (tokenResponse != null) {
      identity.getContextData().put(FEDERATED_ACCESS_TOKEN_RESPONSE, tokenResponse);
      processAccessTokenResponse(identity, tokenResponse);
    }

    return identity;
  }

  private String decryptJWE(String encryptedJWE) {
    try {
      var jwe = new JWE(encryptedJWE);
      var kid = jwe.getHeader().getKeyId();

      // Finding the key from all the realms keys
      var key = session.keys()
          .getKeysStream(session.getContext().getRealm())
          .filter(k -> k.getKid().equalsIgnoreCase(kid))
          .findFirst()
          .map(KeyWrapper::getPrivateKey)
          .orElseThrow(() -> new IdentityBrokerException("No key found for kid " + kid));

      logger.debug("Found corresponding secret key for kid " + kid);
      jwe.getKeyStorage().setDecryptionKey(key);
      return new String(jwe.verifyAndDecodeJwe().getContent());
    } catch (JWEException ex) {
      throw new IdentityBrokerException("Invalid token", ex);
    }
  }

  private SimpleHttp.Response executeRequest(String url, SimpleHttp request) throws IOException {
    var response = request.asResponse();

    if (response.getStatus() != OK.getStatusCode()) {
      throw new IdentityBrokerException("Failed to invoke url [" + url + "]: " + response.asString());
    }

    return response;
  }

  private JsonNode getJsonFromJWT(String jwt) throws IdentityBrokerException {
    JWSInput jwsInput;

    try {
      jwsInput = new JWSInput(jwt);
    } catch (JWSInputException cause) {
      throw new IdentityBrokerException("Failed to parse JWT userinfo response", cause);
    }

    if (!verify(jwsInput)) {
      throw new IdentityBrokerException("Failed to verify signature of of jwt");
    }

    try {
      return JsonSerialization.readValue(jwsInput.getContent(), JsonNode.class);
    } catch (IOException e) {
      throw new IdentityBrokerException("Failed to parse jwt", e);
    }
  }
}
