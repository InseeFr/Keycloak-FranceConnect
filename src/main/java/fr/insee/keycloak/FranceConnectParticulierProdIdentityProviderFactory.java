package fr.insee.keycloak;

import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.broker.social.SocialIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;

public class FranceConnectParticulierProdIdentityProviderFactory
    extends AbstractIdentityProviderFactory<FranceConnectIdentityProvider>
    implements SocialIdentityProviderFactory<FranceConnectIdentityProvider> {


  public static final String PROVIDER_ID = "franceconnect-particulier";

  @Override
  public String getName() {
    return "France Connect Particulier (Production)";
  }

  @Override
  public FranceConnectParticulierProdIdentityProvider create(KeycloakSession session,
      IdentityProviderModel model) {
    return new FranceConnectParticulierProdIdentityProvider(session,
        new FranceConnectIdentityProviderConfig(model));
  }

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

}
