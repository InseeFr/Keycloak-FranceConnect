package fr.insee.keycloak.providers.franceconnect;

import fr.insee.keycloak.providers.common.EidasLevel;
import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.broker.social.SocialIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;

public abstract class AbstractFranceConnectIdentityProviderFactory
    extends AbstractIdentityProviderFactory<FranceConnectIdentityProvider>
    implements SocialIdentityProviderFactory<FranceConnectIdentityProvider> {

  protected abstract FCEnvironment getFCEnvironment();

  protected abstract EidasLevel getEidasLevel();
  @Override
  public FranceConnectIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
    return new FranceConnectIdentityProvider(session, new FranceConnectIdentityProviderConfig(model, getFCEnvironment(), getId()), getEidasLevel());
  }

  @Override
  public FranceConnectIdentityProviderConfig createConfig() {
    return new FranceConnectIdentityProviderConfig(getFCEnvironment(), getId());
  }
}
