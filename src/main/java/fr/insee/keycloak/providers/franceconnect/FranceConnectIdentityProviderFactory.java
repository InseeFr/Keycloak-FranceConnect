package fr.insee.keycloak.providers.franceconnect;

import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.broker.social.SocialIdentityProviderFactory;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;

import java.util.List;

import static fr.insee.keycloak.providers.common.Utils.createHardcodedAttributeMapper;
import static fr.insee.keycloak.providers.common.Utils.createUserAttributeMapper;

public class FranceConnectIdentityProviderFactory
    extends AbstractIdentityProviderFactory<FranceConnectIdentityProvider>
    implements SocialIdentityProviderFactory<FranceConnectIdentityProvider> {

  public static final String FC_PROVIDER_ID = "franceconnect-particulier";
  public static final String FC_PROVIDER_NAME = "France Connect Particulier";

  static final FCEnvironment DEFAULT_FC_ENVIRONMENT = FCEnvironment.INTEGRATION_V1;

  static final List<IdentityProviderMapperModel> FC_PROVIDER_MAPPERS = List.of(
      createUserAttributeMapper(FC_PROVIDER_ID, "lastName", "family_name", "lastName"),
      createUserAttributeMapper(FC_PROVIDER_ID, "firstName", "given_name", "firstName"),
      createUserAttributeMapper(FC_PROVIDER_ID, "email", "email", "email"),
      createHardcodedAttributeMapper(FC_PROVIDER_ID, "provider", "provider", "FC")
  );

  @Override
  public String getName() {
    return FC_PROVIDER_NAME;
  }

  @Override
  public String getId() {
    return FC_PROVIDER_ID;
  }

  @Override
  public FranceConnectIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
    return new FranceConnectIdentityProvider(session, new FranceConnectIdentityProviderConfig(model));
  }

  @Override
  public FranceConnectIdentityProviderConfig createConfig() {
    return new FranceConnectIdentityProviderConfig();
  }
}
