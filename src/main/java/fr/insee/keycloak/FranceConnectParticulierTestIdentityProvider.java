package fr.insee.keycloak;

import org.keycloak.models.KeycloakSession;

public class FranceConnectParticulierTestIdentityProvider extends FranceConnectIdentityProvider {

  public FranceConnectParticulierTestIdentityProvider(KeycloakSession session,
    FranceConnectIdentityProviderConfig config) {
    super(session, config);
    authorizationUrl = "https://fcp.integ01.dev-franceconnect.fr/api/v1/authorize";
    tokenUrl = "https://fcp.integ01.dev-franceconnect.fr/api/v1/token";
    userInfoUrl = "https://fcp.integ01.dev-franceconnect.fr/api/v1/userinfo";
    logoutUrl = "https://fcp.integ01.dev-franceconnect.fr/api/v1/logout";
    init();
  }

}
