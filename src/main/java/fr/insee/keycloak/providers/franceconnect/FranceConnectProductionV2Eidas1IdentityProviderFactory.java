package fr.insee.keycloak.providers.franceconnect;

import fr.insee.keycloak.providers.common.EidasLevel;

public final class FranceConnectProductionV2Eidas1IdentityProviderFactory
    extends AbstractFranceConnectIdentityProviderFactory {

  public static final String FC_PROVIDER_ID = "franceconnect-particulier-production-v2-eidas1";
  public static final String FC_PROVIDER_NAME = "France Connect Particulier V2 - Production - Eidas1";
  public static final FCEnvironment FC_ENVIRONMENT = FCEnvironment.PRODUCTION_V2;
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
