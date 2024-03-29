package fr.insee.keycloak.mappers;

import fr.insee.keycloak.providers.agentconnect.AgentConnectIdentityProviderFactory;
import fr.insee.keycloak.providers.franceconnect.FranceConnectIdentityProviderFactory;
import org.keycloak.broker.oidc.mappers.UserAttributeMapper;

public final class FranceConnectUserAttributeMapper extends UserAttributeMapper {

  public static final String MAPPER_NAME = "franceconnect-user-attribute-mapper";

  private static final String[] COMPATIBLE_PROVIDERS =
      new String[]{
          AgentConnectIdentityProviderFactory.AC_PROVIDER_ID,
          FranceConnectIdentityProviderFactory.FC_PROVIDER_ID
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
