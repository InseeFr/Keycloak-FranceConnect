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

public final class FranceConnectIdentityProviderEidas2Factory
    extends AbstractIdentityProviderFactory<FranceConnectIdentityProviderEidas2>
    implements SocialIdentityProviderFactory<FranceConnectIdentityProviderEidas2> {

  public static final String FC_PROVIDER_ID = "franceconnect-particulier-eidas2";
  public static final String FC_PROVIDER_NAME = "France Connect Particulier Eidas2";

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
  public FranceConnectIdentityProviderEidas2 create(KeycloakSession session, IdentityProviderModel model) {
    return new FranceConnectIdentityProviderEidas2(session, new FranceConnectIdentityProviderConfig(model,FC_PROVIDER_ID));
  }

  @Override
  public OIDCIdentityProviderConfig createConfig() {
    return new FranceConnectIdentityProviderConfig(FC_PROVIDER_ID);
  }
}
