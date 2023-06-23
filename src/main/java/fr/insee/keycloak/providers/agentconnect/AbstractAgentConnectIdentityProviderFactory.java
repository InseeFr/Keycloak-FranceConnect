package fr.insee.keycloak.providers.agentconnect;

import fr.insee.keycloak.providers.common.EidasLevel;
import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.broker.social.SocialIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;

public abstract class AbstractAgentConnectIdentityProviderFactory
    extends AbstractIdentityProviderFactory<AgentConnectIdentityProvider>
    implements SocialIdentityProviderFactory<AgentConnectIdentityProvider> {

  protected abstract ACEnvironment getACEnvironment();

  protected abstract EidasLevel getEidasLevel();
  @Override
  public AgentConnectIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
    return new AgentConnectIdentityProvider(session, new AgentConnectIdentityProviderConfig(model, getACEnvironment(), getId()), getEidasLevel());
  }

  @Override
  public AgentConnectIdentityProviderConfig createConfig() {
    return new AgentConnectIdentityProviderConfig(getACEnvironment(), getId());
  }
}
