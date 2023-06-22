package fr.insee.keycloak.providers.franceconnect;

import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.broker.social.SocialIdentityProviderFactory;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;

import java.util.List;

import static fr.insee.keycloak.providers.common.Utils.createHardcodedAttributeMapper;
import static fr.insee.keycloak.providers.common.Utils.createUserAttributeMapper;

public final class FranceConnectIdentityProviderEidas1Factory
    extends AbstractIdentityProviderFactory<FranceConnectIdentityProviderEidas1>
    implements SocialIdentityProviderFactory<FranceConnectIdentityProviderEidas1> {

  public static final String FC_PROVIDER_ID = "franceconnect-particulier-eidas1";
  public static final String FC_PROVIDER_NAME = "France Connect Particulier Eidas1";

  @Override
  public String getName() {
    return FC_PROVIDER_NAME;
  }

  @Override
  public String getId() {
    return FC_PROVIDER_ID;
  }

  @Override
  public FranceConnectIdentityProviderEidas1 create(KeycloakSession session, IdentityProviderModel model) {
    return new FranceConnectIdentityProviderEidas1(session, new FranceConnectIdentityProviderConfig(model,FC_PROVIDER_ID));
  }

  @Override
  public OIDCIdentityProviderConfig createConfig() {
    return new FranceConnectIdentityProviderConfig(FC_PROVIDER_ID);
  }
}
