package fr.insee.keycloak.providers.agentconnect;

import fr.insee.keycloak.providers.common.AbstractBaseProviderConfig;
import org.keycloak.models.IdentityProviderModel;

class AgentConnectIdentityProviderConfig extends AbstractBaseProviderConfig {

  private static final ACEnvironment DEFAULT_FC_ENVIRONMENT = ACEnvironment.INTEGRATION_INTERNET;

  AgentConnectIdentityProviderConfig(IdentityProviderModel identityProviderModel) {
    super(identityProviderModel);
    initialize();
  }

  AgentConnectIdentityProviderConfig() {
    super();
    initialize();
  }

  private void initialize() {
    var agentConnectEnvironment =
        ACEnvironment.getOrDefault(
            getConfig().get(ACEnvironment.ENVIRONMENT_PROPERTY_NAME), DEFAULT_FC_ENVIRONMENT);

    agentConnectEnvironment.configureUrls(this);

    this.setValidateSignature(true);
    this.setBackchannelSupported(false);
  }
}
