package fr.insee.keycloak;

import java.io.IOException;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;
import org.keycloak.broker.oidc.OIDCIdentityProvider;
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.jose.jws.crypto.HMACProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.IDToken;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.services.resources.IdentityBrokerService;
import org.keycloak.services.resources.RealmsResource;
import org.keycloak.util.JsonSerialization;
import com.fasterxml.jackson.databind.JsonNode;

public class FranceConnectIdentityProvider extends OIDCIdentityProvider
    implements SocialIdentityProvider<OIDCIdentityProviderConfig> {

  protected String authorizationUrl;
  protected String tokenUrl;
  protected String userInfoUrl;
  protected String logoutUrl;


  public FranceConnectIdentityProvider(KeycloakSession session, OIDCIdentityProviderConfig config) {
    super(session, config);
    

  }

  protected void init() {
    this.getConfig().setAuthorizationUrl(getAuthorizationUrl());
    this.getConfig().setTokenUrl(getTokenUrl());
    this.getConfig().setUserInfoUrl(getUserInfoUrl());
    this.getConfig().setLogoutUrl(getLogoutUrl());
    this.getConfig().setValidateSignature(true);
    this.getConfig().setBackchannelSupported(false);
  }
  @Override
  public Response keycloakInitiatedBrowserLogout(KeycloakSession session,
      UserSessionModel userSession, UriInfo uriInfo, RealmModel realm) {
    if (getConfig().getLogoutUrl() == null || getConfig().getLogoutUrl().trim().equals("")) {
      return null;
    }
    String idToken = userSession.getNote(FEDERATED_ID_TOKEN);
    if (idToken != null && getConfig().isBackchannelSupported()) {
      backchannelLogout(userSession, idToken);
      return null;
    } else {
      String sessionId = userSession.getId();
      UriBuilder logoutUri =
          UriBuilder.fromUri(getConfig().getLogoutUrl()).queryParam("state", sessionId);
      if (idToken != null) {
        logoutUri.queryParam("id_token_hint", idToken);
      }
      String redirect =
          RealmsResource.brokerUrl(uriInfo).path(IdentityBrokerService.class, "getEndpoint")
              .path(OIDCEndpoint.class, "logoutResponse")
              .build(realm.getName(), getConfig().getAlias()).toString();
      logoutUri.queryParam("post_logout_redirect_uri", redirect);
      Response response = Response.status(302).location(logoutUri.build()).build();
      return response;
    }
  }


  @Override
  protected boolean verify(JWSInput jws) {
    if (!getConfig().isValidateSignature()) {
      return true;
    }
    return HMACProvider.verify(jws, getConfig().getClientSecret().getBytes());
  }


  @Override
  public void preprocessFederatedIdentity(KeycloakSession session, RealmModel realm,
      BrokeredIdentityContext context) {
    super.preprocessFederatedIdentity(session, realm, context);

  }


  private SimpleHttp.Response executeRequest(String url, SimpleHttp request) throws IOException {
    SimpleHttp.Response response = request.asResponse();
    if (response.getStatus() != 200) {
      String msg = "failed to invoke url [" + url + "]";
      try {
        String tmp = response.asString();
        if (tmp != null)
          msg = tmp;

      } catch (IOException e) {

      }
      throw new IdentityBrokerException("Failed to invoke url [" + url + "]: " + msg);
    }
    return response;
  }

  
  @Override
  protected BrokeredIdentityContext extractIdentity(AccessTokenResponse tokenResponse,
      String accessToken, JsonWebToken idToken) throws IOException {
    String id = idToken.getSubject();
    BrokeredIdentityContext identity = new BrokeredIdentityContext(id);
    String name = (String) idToken.getOtherClaims().get(IDToken.NAME);
    String preferredUsername =
        (String) idToken.getOtherClaims().get(getusernameClaimNameForIdToken());
    String email = (String) idToken.getOtherClaims().get(IDToken.EMAIL);

    if (!getConfig().isDisableUserInfoService()) {
      String userInfoUrl = getUserInfoUrl();
      if (userInfoUrl != null && !userInfoUrl.isEmpty()
          && (id == null || name == null || preferredUsername == null || email == null)) {

        if (accessToken != null) {
          SimpleHttp.Response response = executeRequest(userInfoUrl, SimpleHttp
              .doGet(userInfoUrl, session).header("Authorization", "Bearer " + accessToken));
          String contentType = response.getFirstHeader(HttpHeaders.CONTENT_TYPE);
          JsonNode userInfo;

          if (MediaType.APPLICATION_JSON_TYPE.isCompatible(MediaType.valueOf(contentType))) {
            userInfo = response.asJson();
          } else if ("application/jwt".equals(contentType)) {
            JWSInput jwsInput;

            try {
              jwsInput = new JWSInput(response.asString());
            } catch (JWSInputException cause) {
              throw new RuntimeException("Failed to parse JWT userinfo response", cause);
            }

            if (verify(jwsInput)) {
              userInfo = JsonSerialization.readValue(jwsInput.getContent(), JsonNode.class);
            } else {
              throw new RuntimeException(
                  "Failed to verify signature of userinfo response from [" + userInfoUrl + "].");
            }
          } else {
            throw new RuntimeException("Unsupported content-type [" + contentType
                + "] in response from [" + userInfoUrl + "].");
          }

          id = getJsonProperty(userInfo, "sub");
          name = getJsonProperty(userInfo, "name");
          preferredUsername = getUsernameFromUserInfo(userInfo);
          email = getJsonProperty(userInfo, "email");
          AbstractJsonUserAttributeMapper.storeUserProfileForMapper(identity, userInfo,
              getConfig().getAlias());
        }
      }
    }
    identity.getContextData().put(VALIDATED_ID_TOKEN, idToken);

    identity.setId(id);
    identity.setName(name);
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


  public String getAuthorizationUrl() {
    return authorizationUrl;
  }


  public void setAuthorizationUrl(String authorizationUrl) {
    this.authorizationUrl = authorizationUrl;
  }


  public String getTokenUrl() {
    return tokenUrl;
  }


  public void setTokenUrl(String tokenUrl) {
    this.tokenUrl = tokenUrl;
  }


  public String getUserInfoUrl() {
    return userInfoUrl;
  }


  public void setUserInfoUrl(String userInfoUrl) {
    this.userInfoUrl = userInfoUrl;
  }


  public String getLogoutUrl() {
    return logoutUrl;
  }


  public void setLogoutUrl(String logoutUrl) {
    this.logoutUrl = logoutUrl;
  }



}
