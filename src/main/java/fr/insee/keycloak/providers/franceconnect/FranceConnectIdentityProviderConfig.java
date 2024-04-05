package fr.insee.keycloak.providers.franceconnect;

import static fr.insee.keycloak.providers.franceconnect.FranceConnectIdentityProviderFactory.DEFAULT_FC_ENVIRONMENT;
import static fr.insee.keycloak.providers.franceconnect.FranceConnectIdentityProviderFactory.FC_PROVIDER_MAPPERS;

import fr.insee.keycloak.providers.common.AbstractBaseProviderConfig;
import java.util.List;

import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.IdentityProviderModel;

final class FranceConnectIdentityProviderConfig extends AbstractBaseProviderConfig {

  FranceConnectIdentityProviderConfig(IdentityProviderModel identityProviderModel) {
    super(identityProviderModel);
  }

  FranceConnectIdentityProviderConfig() {
    super();
  }

  @Override
  protected String getEnvironmentProperty(String key) {
    var franceConnectEnvironment =
        FCEnvironment.getOrDefault(
            getConfig().get(FCEnvironment.ENVIRONMENT_PROPERTY_NAME), DEFAULT_FC_ENVIRONMENT);

    return franceConnectEnvironment.getProperty(key);
  }

  @Override
  protected List<IdentityProviderMapperModel> getDefaultMappers() {
    return FC_PROVIDER_MAPPERS;
  }
}
