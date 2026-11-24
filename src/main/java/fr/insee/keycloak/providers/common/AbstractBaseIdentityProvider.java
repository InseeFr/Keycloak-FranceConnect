package fr.insee.keycloak.providers.common;

import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import jakarta.ws.rs.core.UriInfo;
import org.keycloak.broker.oidc.OIDCIdentityProvider;
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.services.resources.IdentityBrokerService;
import org.keycloak.services.resources.RealmsResource;

public abstract class AbstractBaseIdentityProvider<T extends AbstractBaseProviderConfig>
    extends OIDCIdentityProvider implements SocialIdentityProvider<OIDCIdentityProviderConfig> {

  protected static final String ACR_CLAIM_NAME = "acr";

  protected AbstractBaseIdentityProvider(KeycloakSession session, T config) {
    super(session, config);
  }

  @Override
  public T getConfig() {
    return (T) super.getConfig();
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
    // Since Keycloak 26.8 the note is suffixed with the provider alias
    var idToken = userSession.getNote(FEDERATED_ID_TOKEN + ":" + getConfig().getAlias());
    return idToken != null ? idToken : userSession.getNote(FEDERATED_ID_TOKEN);
  }

  @Override
  public BrokeredIdentityContext getFederatedIdentity(String response) {

    try {
      var federatedIdentity = super.getFederatedIdentity(response);

      var idToken = (JsonWebToken) federatedIdentity.getContextData().get(VALIDATED_ID_TOKEN);
      var acrClaim = (String) idToken.getOtherClaims().get(ACR_CLAIM_NAME);

      validateAcrClaim(acrClaim);

      return federatedIdentity;

    } catch (IdentityBrokerException ex) {
      logger.error("Got response " + response);
      throw ex;
    }
  }

  protected void validateAcrClaim(String acrClaim) {
    var returnedEidasLevel = EidasLevel.getOrDefault(acrClaim, null);
    var expectedEidasLevel = getConfig().getEidasLevel();

    if (returnedEidasLevel == null) {
      throw new IdentityBrokerException("The returned eIDAS level cannot be retrieved");
    }

    logger.debugv(
        "Expecting eIDAS level: {0}, actual: {1}", expectedEidasLevel, returnedEidasLevel);

    if (returnedEidasLevel.compareTo(expectedEidasLevel) < 0) {
      throw new IdentityBrokerException("The returned eIDAS level is insufficient");
    }
  }

}
