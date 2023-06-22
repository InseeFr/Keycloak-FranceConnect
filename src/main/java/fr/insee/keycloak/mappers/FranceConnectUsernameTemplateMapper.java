package fr.insee.keycloak.mappers;

import fr.insee.keycloak.providers.agentconnect.AgentConnectIdentityProviderEidas1Factory;
import fr.insee.keycloak.providers.franceconnect.FranceConnectIdentityProviderEidas1Factory;
import org.keycloak.broker.oidc.mappers.UsernameTemplateMapper;

public final class FranceConnectUsernameTemplateMapper extends UsernameTemplateMapper {

  public static final String MAPPER_NAME = "franceconnect-username-template-mapper";

  private static final String[] COMPATIBLE_PROVIDERS =
      new String[]{
          AgentConnectIdentityProviderEidas1Factory.AC_PROVIDER_ID,
          FranceConnectIdentityProviderEidas1Factory.FC_PROVIDER_ID
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
