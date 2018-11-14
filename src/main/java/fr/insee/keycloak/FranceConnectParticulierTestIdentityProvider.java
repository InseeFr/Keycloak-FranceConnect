package fr.insee.keycloak;

import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.models.KeycloakSession;

public class FranceConnectParticulierTestIdentityProvider extends FranceConnectIdentityProvider {


  protected String authorizationUrl = "https://fcp.integ01.dev-franceconnect.fr/api/v1/authorize";
  protected String tokenUrl = "https://fcp.integ01.dev-franceconnect.fr/api/v1/token";
  protected String userInfoUrl = "https://fcp.integ01.dev-franceconnect.fr/api/v1/userinfo";
  protected String logoutUrl = "https://fcp.integ01.dev-franceconnect.fr/api/v1/logout";


  public FranceConnectParticulierTestIdentityProvider(KeycloakSession session,
      OIDCIdentityProviderConfig config) {
    super(session, config);
  }

}
