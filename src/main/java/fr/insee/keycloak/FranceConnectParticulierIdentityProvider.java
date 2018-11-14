package fr.insee.keycloak;

import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.models.KeycloakSession;

public class FranceConnectParticulierIdentityProvider extends FranceConnectIdentityProvider {

  public FranceConnectParticulierIdentityProvider(KeycloakSession session,
      OIDCIdentityProviderConfig config) {
    super(session, config);
  }

}
