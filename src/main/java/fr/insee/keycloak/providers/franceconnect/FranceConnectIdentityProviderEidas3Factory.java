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

public final class FranceConnectIdentityProviderEidas3Factory
    extends AbstractIdentityProviderFactory<FranceConnectIdentityProviderEidas3>
    implements SocialIdentityProviderFactory<FranceConnectIdentityProviderEidas3> {

  public static final String FC_PROVIDER_ID = "franceconnect-particulier-eidas3";
  public static final String FC_PROVIDER_NAME = "France Connect Particulier Eidas3";

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
  public FranceConnectIdentityProviderEidas3 create(KeycloakSession session, IdentityProviderModel model) {
    return new FranceConnectIdentityProviderEidas3(session, new FranceConnectIdentityProviderConfig(model,FC_PROVIDER_ID));
  }

  @Override
  public OIDCIdentityProviderConfig createConfig() {
    return new FranceConnectIdentityProviderConfig(FC_PROVIDER_ID);
  }
}
