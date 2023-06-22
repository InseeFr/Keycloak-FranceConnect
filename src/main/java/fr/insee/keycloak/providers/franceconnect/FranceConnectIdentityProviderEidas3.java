package fr.insee.keycloak.providers.franceconnect;

import fr.insee.keycloak.providers.common.EidasLevel;
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.models.KeycloakSession;

import static fr.insee.keycloak.providers.common.EidasLevel.EIDAS1;
import static fr.insee.keycloak.providers.common.EidasLevel.EIDAS3;

final class FranceConnectIdentityProviderEidas3
    extends AbstractFranceConnectIdentityProvider {

  FranceConnectIdentityProviderEidas3(
      KeycloakSession session, FranceConnectIdentityProviderConfig config) {
    super(
        session,
        config);
  }

  @Override
  protected EidasLevel getEidasLevel() {
    return EIDAS3;
  }
}
