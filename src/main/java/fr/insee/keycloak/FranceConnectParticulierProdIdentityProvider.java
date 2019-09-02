package fr.insee.keycloak;

import org.keycloak.models.KeycloakSession;

public class FranceConnectParticulierProdIdentityProvider extends FranceConnectIdentityProvider {


  public FranceConnectParticulierProdIdentityProvider(KeycloakSession session,
      FranceConnectIdentityProviderConfig config) {
    super(session, config);
    authorizationUrl = "https://app.franceconnect.gouv.fr/api/v1/authorize";
    tokenUrl = "https://app.franceconnect.gouv.fr/api/v1/token";
    userInfoUrl = "https://app.franceconnect.gouv.fr/api/v1/userinfo";
    logoutUrl = "https://app.franceconnect.gouv.fr/api/v1/logout";
    init();

  }

}
