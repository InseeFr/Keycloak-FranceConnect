package fr.insee.keycloak.providers.agentconnect;

import fr.insee.keycloak.providers.common.EidasLevel;
import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.broker.social.SocialIdentityProviderFactory;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static fr.insee.keycloak.providers.common.Utils.createHardcodedAttributeMapper;
import static fr.insee.keycloak.providers.common.Utils.createUserAttributeMapper;

public final class AgentConnectIdentityProviderFactory
    extends AbstractIdentityProviderFactory<AgentConnectIdentityProvider>
    implements SocialIdentityProviderFactory<AgentConnectIdentityProvider> {

  public static final String AC_PROVIDER_ID = "agentconnect";
  public static final String AC_PROVIDER_NAME = "Agent Connect";

  static final ACEnvironment DEFAULT_AC_ENVIRONMENT = ACEnvironment.INTEGRATION_INTERNET;

  static final List<IdentityProviderMapperModel> AC_PROVIDER_MAPPERS = List.of(
      createUserAttributeMapper(AC_PROVIDER_ID, "lastName", "family_name", "lastName"),
      createUserAttributeMapper(AC_PROVIDER_ID, "firstName", "given_name", "firstName"),
      createUserAttributeMapper(AC_PROVIDER_ID, "email", "email", "email"),
      createHardcodedAttributeMapper(AC_PROVIDER_ID, "provider", "provider", "AC")
  );

  @Override
  public String getName() {
    return AC_PROVIDER_NAME;
  }

  @Override
  public String getId() {
    return AC_PROVIDER_ID;
  }

  @Override
  public AgentConnectIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
    return new AgentConnectIdentityProvider(session, new AgentConnectIdentityProviderConfig(model));
  }

  @Override
  public AgentConnectIdentityProviderConfig createConfig() {
    return new AgentConnectIdentityProviderConfig();
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
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
