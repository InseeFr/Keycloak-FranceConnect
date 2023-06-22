package fr.insee.keycloak.providers.franceconnect;

import fr.insee.keycloak.providers.common.AbstractBaseProviderConfig;
import java.util.List;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.IdentityProviderModel;

import static fr.insee.keycloak.providers.common.Utils.createHardcodedAttributeMapper;
import static fr.insee.keycloak.providers.common.Utils.createUserAttributeMapper;

final class FranceConnectIdentityProviderConfig extends AbstractBaseProviderConfig {

  private final String providerID;

  FranceConnectIdentityProviderConfig(IdentityProviderModel identityProviderModel,String providerId) {
    super(identityProviderModel);
    this.providerID=providerId;
  }

  FranceConnectIdentityProviderConfig(String providerId) {
    super();
    this.providerID=providerId;
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
