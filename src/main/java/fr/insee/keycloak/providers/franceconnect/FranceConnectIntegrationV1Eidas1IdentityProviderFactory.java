package fr.insee.keycloak.providers.franceconnect;

import fr.insee.keycloak.providers.common.EidasLevel;
import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.broker.social.SocialIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;

public final class FranceConnectIntegrationV1Eidas1IdentityProviderFactory
    extends AbstractFranceConnectIdentityProviderFactory {

  public static final String FC_PROVIDER_ID = "franceconnect-particulier-integration-v1-eidas1";
  public static final String FC_PROVIDER_NAME = "France Connect Particulier V1 - Integration - Eidas1";
  public static final FCEnvironment FC_ENVIRONMENT = FCEnvironment.INTEGRATION_V1;
  public static final EidasLevel EIDAS_LEVEL = EidasLevel.EIDAS1;

  @Override
  public String getName() {
    return FC_PROVIDER_NAME;
  }

  @Override
  public String getId() {
    return FC_PROVIDER_ID;
  }


  @Override
  protected FCEnvironment getFCEnvironment() {
    return FC_ENVIRONMENT;
  }

  @Override
  protected EidasLevel getEidasLevel() {
    return EIDAS_LEVEL;
  }
}
