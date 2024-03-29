package fr.insee.keycloak.providers.franceconnect;

import static fr.insee.keycloak.providers.franceconnect.FranceConnectIdentityProviderFactory.DEFAULT_FC_ENVIRONMENT;
import static fr.insee.keycloak.providers.franceconnect.FranceConnectIdentityProviderFactory.FC_PROVIDER_MAPPERS;

import fr.insee.keycloak.providers.common.AbstractBaseProviderConfig;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import fr.insee.keycloak.providers.common.EidasLevel;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

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

  public static List<ProviderConfigProperty> getConfigProperties() {
    List<String> environments = Stream.of(FCEnvironment.values())
        .map(Enum::name)
        .collect(Collectors.toList());

    List<String> eidasLevels = Stream.of(EidasLevel.values())
        .map(Enum::name)
        .collect(Collectors.toList());

    return ProviderConfigurationBuilder.create()
        .property().name(FCEnvironment.ENVIRONMENT_PROPERTY_NAME)
          .label("Environnement FranceConnect")
          .helpText("Permet de choisir l'environnement FranceConnect. Effet : change les urls vers FranceConnect.")
          .type(ProviderConfigProperty.LIST_TYPE)
          .options(environments)
          .defaultValue(DEFAULT_FC_ENVIRONMENT)
          .add()
        .property().name(EidasLevel.EIDAS_LEVEL_PROPERTY_NAME)
          .label("Niveau de garantie eIDAS")
          .helpText("Permet de fixer le niveau de garantie du compte utilisateur souhaité. Effet : désactive des fournisseurs d'identités (FI) sur la page de login FranceConnect.")
          .type(ProviderConfigProperty.LIST_TYPE)
          .options(eidasLevels)
          .defaultValue(EidasLevel.EIDAS1)
          .add()
        .build();
  }
}
