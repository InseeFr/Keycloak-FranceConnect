package fr.insee.keycloak.providers.agentconnect;

import fr.insee.keycloak.providers.common.EidasLevel;
import org.keycloak.OAuth2Constants;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.models.KeycloakSession;

import javax.ws.rs.core.UriBuilder;

public final class AgentConnectIdentityProviderEidas3
    extends AbstractAgentConnectIdentityProvider {

  AgentConnectIdentityProviderEidas3(KeycloakSession session, AgentConnectIdentityProviderConfig config) {
    super(session, config);
  }

  @Override
  protected EidasLevel getEidasLevel(){
    return EidasLevel.EIDAS3;
  }

  @Override
  protected UriBuilder createAuthorizationUrl(AuthenticationRequest request) {

    var config = getConfig();

    request
        .getAuthenticationSession()
        .setClientNote(OAuth2Constants.ACR_VALUES, getEidasLevel().toString());
    var uriBuilder = super.createAuthorizationUrl(request);

    logger.debugv("AgentConnect Authorization Url: {0}", uriBuilder.build().toString());

    return uriBuilder;
  }
}
