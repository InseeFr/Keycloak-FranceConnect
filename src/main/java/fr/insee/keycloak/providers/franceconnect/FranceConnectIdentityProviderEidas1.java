package fr.insee.keycloak.providers.franceconnect;

import fr.insee.keycloak.providers.common.AbstractBaseProviderConfig;
import fr.insee.keycloak.providers.common.EidasLevel;
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.models.KeycloakSession;

import static fr.insee.keycloak.providers.common.EidasLevel.EIDAS1;

final class FranceConnectIdentityProviderEidas1
    extends AbstractFranceConnectIdentityProvider {

  FranceConnectIdentityProviderEidas1(
      KeycloakSession session, FranceConnectIdentityProviderConfig config) {
    super(
        session,
        config);
  }

  @Override
  protected EidasLevel getEidasLevel() {
    return EIDAS1;
  }
}
