package fr.insee.keycloak.providers.agentconnect;

import fr.insee.keycloak.providers.common.AbstractBaseProviderConfig;
import org.keycloak.models.IdentityProviderModel;

class AgentConnectIdentityProviderConfig extends AbstractBaseProviderConfig {

  private static final ACEnvironment DEFAULT_AC_ENVIRONMENT = ACEnvironment.INTEGRATION_INTERNET;

  AgentConnectIdentityProviderConfig(IdentityProviderModel identityProviderModel) {
    super(identityProviderModel);
  }

  AgentConnectIdentityProviderConfig() {
    super();
  }

  @Override
  protected String getEnvironmentProperty(String key) {

    var agentConnectEnvironment = ACEnvironment.getOrDefault(
        getConfig().get(ACEnvironment.ENVIRONMENT_PROPERTY_NAME),
        DEFAULT_AC_ENVIRONMENT
    );

    return agentConnectEnvironment.getProperty(key);
  }
}
