package fr.insee.keycloak.providers.franceconnect;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;

public class FranceConnectAutoLinkAuthenticatorFactory implements AuthenticatorFactory {
  public static final String PROVIDER_ID = "franceconnect--auto-link";
  static FranceConnectAutoLinkAuthenticator SINGLETON = new FranceConnectAutoLinkAuthenticator();

  @Override
  public Authenticator create(KeycloakSession keycloakSession) {
    return SINGLETON;
  }

  @Override
  public void init(Config.Scope scope) {
  }

  @Override
  public void postInit(KeycloakSessionFactory keycloakSessionFactory) {
  }

  @Override
  public void close() {
  }

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  @Override
  public String getReferenceCategory() {
    return "franceConnectAutoLink";
  }

  @Override
  public boolean isConfigurable() {
    return false;
  }

  @Override
  public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
    return REQUIREMENT_CHOICES;
  }

  @Override
  public boolean isUserSetupAllowed() {
    return false;
  }

  @Override
  public String getDisplayType() {
    return "FranceConnect: automatically link account";
  }

  @Override
  public String getHelpText() {
    return "Use the FranceConnect identity (\"identité pivot\") to automatically link the Keycloak account";
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return null;
  }
}
