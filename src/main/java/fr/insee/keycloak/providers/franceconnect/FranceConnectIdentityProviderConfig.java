package fr.insee.keycloak.providers.franceconnect;

import fr.insee.keycloak.providers.common.EidasLevel;
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.models.IdentityProviderModel;

class FranceConnectIdentityProviderConfig extends OIDCIdentityProviderConfig {

  private static final EidasLevel DEFAULT_EIDAS_LEVEL = EidasLevel.EIDAS1;
  private static final FCEnvironment DEFAULT_FC_ENVIRONMENT = FCEnvironment.INTEGRATION_V1;

  FranceConnectIdentityProviderConfig(IdentityProviderModel identityProviderModel) {
    super(identityProviderModel);

    initialize();
  }

  FranceConnectIdentityProviderConfig() {
    super();
    initialize();
  }

  private void initialize() {
    var franceConnectEnvironment =
        FCEnvironment.getOrDefault(
            getConfig().get(FCEnvironment.ENVIRONMENT_PROPERTY_NAME), DEFAULT_FC_ENVIRONMENT);

    franceConnectEnvironment.configureUrls(this);

    this.setValidateSignature(true);
    this.setBackchannelSupported(false);
  }

  boolean isIgnoreAbsentStateParameterLogout() {
    return Boolean.parseBoolean(getConfig().get("ignoreAbsentStateParameterLogout"));
  }

  EidasLevel getEidasLevel() {
    return EidasLevel.getOrDefault(
        getConfig().get(EidasLevel.EIDAS_LEVEL_PROPERTY_NAME), DEFAULT_EIDAS_LEVEL);
  }

}
