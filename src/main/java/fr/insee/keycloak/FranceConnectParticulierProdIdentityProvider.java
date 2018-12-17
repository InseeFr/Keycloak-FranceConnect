package fr.insee.keycloak;

import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.models.KeycloakSession;

public class FranceConnectParticulierProdIdentityProvider extends FranceConnectIdentityProvider {


  protected String authorizationUrl = "https://app.franceconnect.gouv.fr/api/v1/authorize";
  protected String tokenUrl = "https://app.franceconnect.gouv.fr/api/v1/token";
  protected String userInfoUrl = "https://app.franceconnect.gouv.fr/api/v1/userinfo";
  protected String logoutUrl = "https://app.franceconnect.gouv.fr/api/v1/logout";


  public FranceConnectParticulierProdIdentityProvider(KeycloakSession session,
      OIDCIdentityProviderConfig config) {
    super(session, config);
    authorizationUrl = "https://app.franceconnect.gouv.fr/api/v1/authorize";
    tokenUrl = "https://app.franceconnect.gouv.fr/api/v1/token";
    userInfoUrl = "https://app.franceconnect.gouv.fr/api/v1/userinfo";
    logoutUrl = "https://app.franceconnect.gouv.fr/api/v1/logout";
    init();

  }

}
