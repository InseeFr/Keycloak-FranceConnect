package fr.insee.keycloak.providers.franceconnect;

import fr.insee.keycloak.providers.common.AbstractBaseProviderConfig;
import org.keycloak.models.IdentityProviderModel;

class FranceConnectIdentityProviderConfig extends AbstractBaseProviderConfig {

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
}
