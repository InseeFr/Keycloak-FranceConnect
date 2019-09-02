package fr.insee.keycloak;

import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.broker.social.SocialIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;

public class FranceConnectParticulierTestIdentityProviderFactory
    extends AbstractIdentityProviderFactory<FranceConnectIdentityProvider>
    implements SocialIdentityProviderFactory<FranceConnectIdentityProvider> {

  public static final String PROVIDER_ID = "franceconnect-particulier-test";
  
  @Override
  public String getName() {
    return "France Connect Particulier (Integration)";
  }

  @Override
  public FranceConnectParticulierTestIdentityProvider create(KeycloakSession session,
      IdentityProviderModel model) {
    return new FranceConnectParticulierTestIdentityProvider(session,
        new FranceConnectIdentityProviderConfig(model));
  }

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

}
