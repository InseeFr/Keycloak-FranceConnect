package fr.insee.keycloak.providers.agentconnect;

import fr.insee.keycloak.providers.common.AbstractBaseProviderConfig;
import fr.insee.keycloak.providers.common.EidasLevel;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static fr.insee.keycloak.providers.agentconnect.AgentConnectIdentityProviderFactory.AC_PROVIDER_MAPPERS;
import static fr.insee.keycloak.providers.agentconnect.AgentConnectIdentityProviderFactory.DEFAULT_AC_ENVIRONMENT;

final class AgentConnectIdentityProviderConfig extends AbstractBaseProviderConfig {

  AgentConnectIdentityProviderConfig(IdentityProviderModel identityProviderModel) {
    super(identityProviderModel);
  }

  AgentConnectIdentityProviderConfig() {
    super();
  }

  @Override
  protected String getEnvironmentProperty(String key) {

    var agentConnectEnvironment = ACEnvironment.getOrDefault(
        getConfig().get(ACEnvironment.ENVIRONMENT_PROPERTY_NAME),
        DEFAULT_AC_ENVIRONMENT
    );

    return agentConnectEnvironment.getProperty(key);
  }

  @Override
  protected List<IdentityProviderMapperModel> getDefaultMappers() {
    return AC_PROVIDER_MAPPERS;
  }

  public static List<ProviderConfigProperty> getConfigProperties() {
    List<String> environments = Stream.of(ACEnvironment.values())
        .map(Enum::name)
        .collect(Collectors.toList());

    List<String> eidasLevels = Stream.of(EidasLevel.values())
        .map(Enum::name)
        .collect(Collectors.toList());

    return ProviderConfigurationBuilder.create()
        .property().name(ACEnvironment.ENVIRONMENT_PROPERTY_NAME)
        .label("Environnement AgentConnect")
        .helpText("Permet de choisir l'environnement AgentConnect. Effet : change les urls vers AgentConnect.")
        .type(ProviderConfigProperty.LIST_TYPE)
        .options(environments)
        .defaultValue(DEFAULT_AC_ENVIRONMENT)
        .add()
        .property().name(EidasLevel.EIDAS_LEVEL_PROPERTY_NAME)
        .label("Niveau de garantie eIDAS")
        .helpText("Permet de fixer le niveau de garantie du compte utilisateur souhaité. Effet : désactive des fournisseurs d'identités (FI) sur la page de login AgentConnect.")
        .type(ProviderConfigProperty.LIST_TYPE)
        .options(eidasLevels)
        .defaultValue(EidasLevel.EIDAS1)
        .add()
        .build();
  }
}
