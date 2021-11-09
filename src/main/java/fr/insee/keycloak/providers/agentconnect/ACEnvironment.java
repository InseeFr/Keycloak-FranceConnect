package fr.insee.keycloak.providers.agentconnect;

import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;

enum ACEnvironment {
  INTEGRATION_RIE("https://fca.integ02.agentconnect.rie.gouv.fr", 2),
  PRODUCTION_RIE("", 1),
  INTEGRATION_INTERNET("https://fca.integ01.dev-agentconnect.fr", 2),
  PRODUCTION_INTERNET("", 2);

  static final String ENVIRONMENT_PROPERTY_NAME = "fc_environment";

  private final String baseUrl;

  private final int version;

  ACEnvironment(String baseUrl, int version) {
    this.baseUrl = baseUrl;
    this.version = version;
  }

  void configureUrls(OIDCIdentityProviderConfig config) {
    if (version == 1) {
      config.setAuthorizationUrl(baseUrl + "/api/v1/authorize");
      config.setTokenUrl(baseUrl + "/api/v1/token");
      config.setUserInfoUrl(baseUrl + "/api/v1/userinfo");
      config.setLogoutUrl(baseUrl + "/api/v1/logout");
    } else if (version == 2) {
      config.setAuthorizationUrl(baseUrl + "/api/v2/authorize");
      config.setTokenUrl(baseUrl + "/api/v2/token");
      config.setUserInfoUrl(baseUrl + "/api/v2/userinfo");
      config.setLogoutUrl(baseUrl + "/api/v2/session/end");
      config.setIssuer(baseUrl + "/api/v2");
      config.setJwksUrl(baseUrl + "/api/v2/jwks");
      config.setUseJwksUrl(true);
    }
  }

  static ACEnvironment getOrDefault(String environmentName, ACEnvironment defaultEnvironment) {
    for (var environment : ACEnvironment.values()) {
      if (environment.name().equalsIgnoreCase(environmentName)) {
        return environment;
      }
    }

    return defaultEnvironment;
  }
}
