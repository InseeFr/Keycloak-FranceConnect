package fr.insee.keycloak.providers.agentconnect;

import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.models.IdentityProviderModel;

class AgentConnectIdentityProviderConfig extends OIDCIdentityProviderConfig {

  private static final EidasLevel DEFAULT_EIDAS_LEVEL = EidasLevel.EIDAS1;
  private static final Environment DEFAULT_FC_ENVIRONMENT = Environment.INTEGRATION_INTERNET;

  AgentConnectIdentityProviderConfig(IdentityProviderModel identityProviderModel) {
    super(identityProviderModel);

    initialize();
  }

  AgentConnectIdentityProviderConfig() {
    super();
    initialize();
  }

  private void initialize() {
    var agentConnectEnvironment =
        Environment.getOrDefault(
            getConfig().get(Environment.ENVIRONMENT_PROPERTY_NAME), DEFAULT_FC_ENVIRONMENT);

    agentConnectEnvironment.configureUrls(this);

    this.setValidateSignature(true);
    this.setBackchannelSupported(false);
  }

  boolean isIgnoreAbsentStateParameterLogout() {
    return Boolean.parseBoolean(getConfig().get("ignoreAbsentStateParameterLogout"));
  }

  EidasLevel getEidasLevel() {
    return EidasLevel.getOrDefault(
        getConfig().get(EidasLevel.EIDAS_LEVEL_PROPERTY_NAME), DEFAULT_EIDAS_LEVEL);
  }

  enum EidasLevel {
    EIDAS1,
    EIDAS2,
    EIDAS3;

    static final String EIDAS_LEVEL_PROPERTY_NAME = "eidas_values";

    @Override
    public String toString() {
      return name().toLowerCase();
    }

    static EidasLevel getOrDefault(String eidasLevelName, EidasLevel defaultEidasLevel) {
      for (var eidasLevel : EidasLevel.values()) {
        if (eidasLevel.name().equalsIgnoreCase(eidasLevelName)) {
          return eidasLevel;
        }
      }

      return defaultEidasLevel;
    }
  }

  enum Environment {
    INTEGRATION_RIE("https://fca.integ02.agentconnect.rie.gouv.fr", 2),
    PRODUCTION_RIE("", 1),
    INTEGRATION_INTERNET("https://fca.integ01.dev-agentconnect.fr", 2),
    PRODUCTION_INTERNET("", 2);

    static final String ENVIRONMENT_PROPERTY_NAME = "fc_environment";

    private final String baseUrl;

    private final int version;

    Environment(String baseUrl, int version) {
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

    static Environment getOrDefault(String environmentName, Environment defaultEnvironment) {
      for (var environment : Environment.values()) {
        if (environment.name().equalsIgnoreCase(environmentName)) {
          return environment;
        }
      }

      return defaultEnvironment;
    }
  }
}
