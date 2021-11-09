package fr.insee.keycloak.providers.agentconnect;

import fr.insee.keycloak.providers.common.EidasLevel;
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.models.IdentityProviderModel;

class AgentConnectIdentityProviderConfig extends OIDCIdentityProviderConfig {

  private static final EidasLevel DEFAULT_EIDAS_LEVEL = EidasLevel.EIDAS1;
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

  boolean isIgnoreAbsentStateParameterLogout() {
    return Boolean.parseBoolean(getConfig().get("ignoreAbsentStateParameterLogout"));
  }

  EidasLevel getEidasLevel() {
    return EidasLevel.getOrDefault(
        getConfig().get(EidasLevel.EIDAS_LEVEL_PROPERTY_NAME), DEFAULT_EIDAS_LEVEL);
  }

}
