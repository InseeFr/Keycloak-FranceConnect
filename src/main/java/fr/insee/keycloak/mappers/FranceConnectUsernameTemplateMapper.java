package fr.insee.keycloak.mappers;

import fr.insee.keycloak.provider.AgentConnectIdentityProviderFactory;
import fr.insee.keycloak.provider.FranceConnectIdentityProviderFactory;
import org.keycloak.broker.oidc.mappers.UsernameTemplateMapper;

public class FranceConnectUsernameTemplateMapper extends UsernameTemplateMapper {

  private static final String MAPPER_NAME = "franceconnect-username-template-mapper";

  public static final String[] COMPATIBLE_PROVIDERS =
      new String[] {
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
