package fr.insee.keycloak.providers.agentconnect;

import fr.insee.keycloak.providers.common.AbstractBaseProviderConfig;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.IdentityProviderModel;

import java.util.List;

import static fr.insee.keycloak.providers.common.Utils.createHardcodedAttributeMapper;
import static fr.insee.keycloak.providers.common.Utils.createUserAttributeMapper;

final class AgentConnectIdentityProviderConfig extends AbstractBaseProviderConfig {

  AgentConnectIdentityProviderConfig(IdentityProviderModel identityProviderModel, ACEnvironment acEnvironment, String providerId) {
    super(identityProviderModel, acEnvironment, providerId);
  }

  AgentConnectIdentityProviderConfig(ACEnvironment acEnvironment, String providerId) {
    super(acEnvironment, providerId);
  }

  @Override
  protected List<IdentityProviderMapperModel> getDefaultMappers() {
    return List.of(
        createUserAttributeMapper(providerID, "lastName", "family_name", "lastName"),
        createUserAttributeMapper(providerID, "firstName", "given_name", "firstName"),
        createUserAttributeMapper(providerID, "email", "email", "email"),
        createHardcodedAttributeMapper(providerID, "provider", "provider", "AC")
    );
  }
}
