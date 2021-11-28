package fr.insee.keycloak.providers.agentconnect;

import fr.insee.keycloak.providers.common.AbstractBaseProviderConfig;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.IdentityProviderModel;

import java.util.List;

import static fr.insee.keycloak.providers.agentconnect.AgentConnectIdentityProviderFactory.AC_PROVIDER_MAPPERS;
import static fr.insee.keycloak.providers.agentconnect.AgentConnectIdentityProviderFactory.DEFAULT_AC_ENVIRONMENT;

class AgentConnectIdentityProviderConfig extends AbstractBaseProviderConfig {

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

  @Override
  protected List<IdentityProviderMapperModel> getDefaultMappers() {
    return AC_PROVIDER_MAPPERS;
  }
}
