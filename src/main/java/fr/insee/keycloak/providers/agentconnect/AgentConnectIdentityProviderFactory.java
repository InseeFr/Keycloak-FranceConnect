package fr.insee.keycloak.providers.agentconnect;

import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.broker.social.SocialIdentityProviderFactory;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;

import java.util.List;

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
}
