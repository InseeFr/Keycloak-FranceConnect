package fr.insee.keycloak.mappers;

import fr.insee.keycloak.providers.agentconnect.AgentConnectIntegrationRieEidas1IdentityProviderFactory;
import fr.insee.keycloak.providers.franceconnect.FranceConnectIntegrationV1Eidas1IdentityProviderFactory;
import org.keycloak.broker.oidc.mappers.UsernameTemplateMapper;

public final class FranceConnectUsernameTemplateMapper extends UsernameTemplateMapper {

  public static final String MAPPER_NAME = "franceconnect-username-template-mapper";

  private static final String[] COMPATIBLE_PROVIDERS =
      new String[]{
          AgentConnectIntegrationRieEidas1IdentityProviderFactory.AC_PROVIDER_ID,
          FranceConnectIntegrationV1Eidas1IdentityProviderFactory.FC_PROVIDER_ID
      };

  @Override
  public String[] getCompatibleProviders() {
    return COMPATIBLE_PROVIDERS;
  }

  @Override
  public String getId() {
    return MAPPER_NAME;
  }
}
