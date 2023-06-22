package fr.insee.keycloak.providers.agentconnect;

import fr.insee.keycloak.providers.common.AbstractBaseProviderConfig;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.IdentityProviderModel;

import java.util.List;

import static fr.insee.keycloak.providers.common.Utils.createHardcodedAttributeMapper;
import static fr.insee.keycloak.providers.common.Utils.createUserAttributeMapper;

final class AgentConnectIdentityProviderConfig extends AbstractBaseProviderConfig {

  private final String providerId;

  AgentConnectIdentityProviderConfig(IdentityProviderModel identityProviderModel, String providerId) {
    super(identityProviderModel);
    this.providerId = providerId;
  }

  AgentConnectIdentityProviderConfig(String providerId) {
    super();
    this.providerId = providerId;
  }

  @Override
  protected List<IdentityProviderMapperModel> getDefaultMappers() {
    return List.of(
        createUserAttributeMapper(providerId, "lastName", "family_name", "lastName"),
        createUserAttributeMapper(providerId, "firstName", "given_name", "firstName"),
        createUserAttributeMapper(providerId, "email", "email", "email"),
        createHardcodedAttributeMapper(providerId, "provider", "provider", "AC")
    );
  }
}
