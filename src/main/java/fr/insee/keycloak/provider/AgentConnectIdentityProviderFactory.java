package fr.insee.keycloak.provider;

import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.broker.social.SocialIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;

public class AgentConnectIdentityProviderFactory
    extends AbstractIdentityProviderFactory<AgentConnectIdentityProvider>
    implements SocialIdentityProviderFactory<AgentConnectIdentityProvider> {

  public static final String AC_PROVIDER_ID = "agentconnect";
  public static final String AC_PROVIDER_NAME = "Agent Connect";

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
