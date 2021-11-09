package fr.insee.keycloak.providers.franceconnect;

import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.models.IdentityProviderModel;

class FranceConnectIdentityProviderConfig extends OIDCIdentityProviderConfig {

  private static final EidasLevel DEFAULT_EIDAS_LEVEL = EidasLevel.EIDAS1;
  private static final Environment DEFAULT_FC_ENVIRONMENT = Environment.INTEGRATION_V1;

  FranceConnectIdentityProviderConfig(IdentityProviderModel identityProviderModel) {
    super(identityProviderModel);

    initialize();
  }

  FranceConnectIdentityProviderConfig() {
    super();
    initialize();
  }

  private void initialize() {
    Environment franceConnectEnvironment =
        Environment.getOrDefault(
            getConfig().get(Environment.ENVIRONMENT_PROPERTY_NAME), DEFAULT_FC_ENVIRONMENT);

    franceConnectEnvironment.configureUrls(this);

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
      for (EidasLevel eidasLevel : EidasLevel.values()) {
        if (eidasLevel.name().equalsIgnoreCase(eidasLevelName)) {
          return eidasLevel;
        }
      }

      return defaultEidasLevel;
    }
  }

  enum Environment {
    INTEGRATION_V1("https://fcp.integ01.dev-franceconnect.fr", 1),
    PRODUCTION_V1("https://app.franceconnect.gouv.fr", 1),
    INTEGRATION_V2("https://auth.integ01.dev-franceconnect.fr", 2),
    PRODUCTION_V2("https://auth.franceconnect.gouv.fr", 2),
    ;

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
        config.setLogoutUrl(baseUrl + "/api/v2/logout");
        config.setIssuer(baseUrl + "/api/v2");
        config.setJwksUrl(baseUrl + "/api/v2/jwks");
        config.setUseJwksUrl(true);
      }
    }

    static Environment getOrDefault(String environmentName, Environment defaultEnvironment) {
      for (Environment environment : Environment.values()) {
        if (environment.name().equalsIgnoreCase(environmentName)) {
          return environment;
        }
      }

      return defaultEnvironment;
    }
  }
}
