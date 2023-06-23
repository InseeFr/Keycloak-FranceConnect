package fr.insee.keycloak.providers.franceconnect;

import static fr.insee.keycloak.providers.common.Utils.createHardcodedAttributeMapper;
import static fr.insee.keycloak.providers.common.Utils.createUserAttributeMapper;

import fr.insee.keycloak.providers.common.AbstractBaseProviderConfig;
import java.util.List;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.IdentityProviderModel;

final class FranceConnectIdentityProviderConfig extends AbstractBaseProviderConfig {

  FranceConnectIdentityProviderConfig(IdentityProviderModel identityProviderModel, FCEnvironment fcEnvironment, String providerId) {
    super(identityProviderModel,fcEnvironment, providerId);
  }

  FranceConnectIdentityProviderConfig(FCEnvironment fcEnvironment,String providerId) {
    super(fcEnvironment, providerId);
  }

  @Override
  protected List<IdentityProviderMapperModel> getDefaultMappers() {
    return List.of(
        createUserAttributeMapper(providerID, "lastName", "family_name", "lastName"),
        createUserAttributeMapper(providerID, "firstName", "given_name", "firstName"),
        createUserAttributeMapper(providerID, "email", "email", "email"),
        createHardcodedAttributeMapper(providerID, "provider", "provider", "FC")
    );
  }
}
