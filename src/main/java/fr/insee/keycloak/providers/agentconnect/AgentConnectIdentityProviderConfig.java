package fr.insee.keycloak.providers.agentconnect;

import fr.insee.keycloak.providers.common.AbstractBaseProviderConfig;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.IdentityProviderModel;

import java.util.List;

import static fr.insee.keycloak.providers.agentconnect.AgentConnectIdentityProviderFactory.getAcProviderMappers;
import static fr.insee.keycloak.providers.agentconnect.AgentConnectIdentityProviderFactory.DEFAULT_AC_ENVIRONMENT;

final class AgentConnectIdentityProviderConfig extends AbstractBaseProviderConfig {

  // Superseded by MfaRequirement.MFA_MODE_PROPERTY_NAME; kept only to migrate realms configured
  // before the 2FA toggle became a 3-way DISABLED/OPTIONAL/REQUIRED choice.
  static final String LEGACY_MFA_ENABLED_PROPERTY_NAME = "mfa_enabled";

  public MfaRequirement getMfaRequirement() {
    var configuredMode = getConfig().get(MfaRequirement.MFA_MODE_PROPERTY_NAME);
    if (configuredMode != null) {
      return MfaRequirement.getOrDefault(configuredMode, MfaRequirement.DISABLED);
    }

    return Boolean.parseBoolean(getConfig().get(LEGACY_MFA_ENABLED_PROPERTY_NAME))
        ? MfaRequirement.REQUIRED
        : MfaRequirement.DISABLED;
  }

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
    return getAcProviderMappers();
  }
}
