package fr.insee.keycloak;

import org.keycloak.broker.oidc.mappers.UsernameTemplateMapper;

public class FranceConnectUsernameTemplateMapper extends UsernameTemplateMapper{

  private static final String[] cp =
      new String[] {
          FranceConnectParticulierProdIdentityProviderFactory.PROVIDER_ID,
          FranceConnectParticulierTestIdentityProviderFactory.PROVIDER_ID};

  @Override
  public String[] getCompatibleProviders() {
    return cp;
  }

  @Override
  public String getId() {
    return "franceconnect-username-template-mapper";
  }

}
