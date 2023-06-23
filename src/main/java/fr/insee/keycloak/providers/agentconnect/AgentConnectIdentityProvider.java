package fr.insee.keycloak.providers.agentconnect;

import fr.insee.keycloak.providers.common.AbstractBaseIdentityProvider;
import fr.insee.keycloak.providers.common.EidasLevel;
import fr.insee.keycloak.providers.common.Utils;

import javax.ws.rs.core.UriBuilder;

import org.keycloak.OAuth2Constants;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.models.KeycloakSession;

final class AgentConnectIdentityProvider
    extends AbstractBaseIdentityProvider<AgentConnectIdentityProviderConfig> {

  AgentConnectIdentityProvider(KeycloakSession session, AgentConnectIdentityProviderConfig config, EidasLevel eidasLevel) {
    super(session, config, Utils.getJsonWebKeySetFrom(config.getJwksUrl(), session), eidasLevel);
  }

  @Override
  protected UriBuilder createAuthorizationUrl(AuthenticationRequest request) {

    var config = getConfig();

    request
        .getAuthenticationSession()
        .setClientNote(OAuth2Constants.ACR_VALUES, eidasLevel.toString());
    var uriBuilder = super.createAuthorizationUrl(request);

    logger.debugv("AgentConnect Authorization Url: {0}", uriBuilder.build().toString());

    return uriBuilder;
  }
}
