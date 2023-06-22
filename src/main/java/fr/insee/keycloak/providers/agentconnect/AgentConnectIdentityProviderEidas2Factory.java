package fr.insee.keycloak.providers.agentconnect;

import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.broker.social.SocialIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;

public final class AgentConnectIdentityProviderEidas2Factory
    extends AbstractIdentityProviderFactory<AgentConnectIdentityProviderEidas2>
    implements SocialIdentityProviderFactory<AgentConnectIdentityProviderEidas2> {

  public static final String AC_PROVIDER_ID = "agentconnect-eidas2";
  public static final String AC_PROVIDER_NAME = "Agent Connect Eidas2";

  @Override
  public String getName() {
    return AC_PROVIDER_NAME;
  }

  @Override
  public String getId() {
    return AC_PROVIDER_ID;
  }

  @Override
  public AgentConnectIdentityProviderEidas2 create(KeycloakSession session, IdentityProviderModel model) {
    return new AgentConnectIdentityProviderEidas2(session, new AgentConnectIdentityProviderConfig(model,AC_PROVIDER_ID));
  }

  @Override
  public OIDCIdentityProviderConfig createConfig() {
    return new AgentConnectIdentityProviderConfig(AC_PROVIDER_ID);
  }
}
