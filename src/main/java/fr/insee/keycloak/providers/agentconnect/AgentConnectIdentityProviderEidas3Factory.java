package fr.insee.keycloak.providers.agentconnect;

import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.broker.social.SocialIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;

public final class AgentConnectIdentityProviderEidas3Factory
    extends AbstractIdentityProviderFactory<AgentConnectIdentityProviderEidas3>
    implements SocialIdentityProviderFactory<AgentConnectIdentityProviderEidas3> {

  public static final String AC_PROVIDER_ID = "agentconnect-eidas3";
  public static final String AC_PROVIDER_NAME = "Agent Connect Eidas3";

  @Override
  public String getName() {
    return AC_PROVIDER_NAME;
  }

  @Override
  public String getId() {
    return AC_PROVIDER_ID;
  }

  @Override
  public AgentConnectIdentityProviderEidas3 create(KeycloakSession session, IdentityProviderModel model) {
    return new AgentConnectIdentityProviderEidas3(session, new AgentConnectIdentityProviderConfig(model,AC_PROVIDER_ID));
  }

  @Override
  public OIDCIdentityProviderConfig createConfig() {
    return new AgentConnectIdentityProviderConfig(AC_PROVIDER_ID);
  }
}
