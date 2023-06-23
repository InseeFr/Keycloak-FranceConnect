package fr.insee.keycloak.providers.agentconnect;

import fr.insee.keycloak.providers.common.EidasLevel;
import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.broker.social.SocialIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;

public final class AgentConnectIntegrationRieEidas1IdentityProviderFactory
    extends AbstractAgentConnectIdentityProviderFactory {

  public static final String AC_PROVIDER_ID = "agentconnect-integration-rie-eidas1";
  public static final String AC_PROVIDER_NAME = "Agent Connect RIE - Integration - Eidas1";
  public static final ACEnvironment AC_ENVIRONMENT = ACEnvironment.INTEGRATION_RIE;
  public static final EidasLevel EIDAS_LEVEL = EidasLevel.EIDAS1;

  @Override
  public String getName() {
    return AC_PROVIDER_NAME;
  }

  @Override
  public String getId() {
    return AC_PROVIDER_ID;
  }

  @Override
  protected ACEnvironment getACEnvironment() {
    return AC_ENVIRONMENT;
  }

  @Override
  protected EidasLevel getEidasLevel() {
    return EIDAS_LEVEL;
  }
}
