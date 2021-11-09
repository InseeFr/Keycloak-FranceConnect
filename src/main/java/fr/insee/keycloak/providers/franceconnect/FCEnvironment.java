package fr.insee.keycloak.providers.franceconnect;

import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;

enum FCEnvironment {
    INTEGRATION_V1("https://fcp.integ01.dev-franceconnect.fr", 1),
    PRODUCTION_V1("https://app.franceconnect.gouv.fr", 1),
    INTEGRATION_V2("https://auth.integ01.dev-franceconnect.fr", 2),
    PRODUCTION_V2("https://auth.franceconnect.gouv.fr", 2);

    static final String ENVIRONMENT_PROPERTY_NAME = "fc_environment";

    private final String baseUrl;
    private final int version;

    FCEnvironment(String baseUrl, int version) {
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

    static FCEnvironment getOrDefault(String environmentName, FCEnvironment defaultEnvironment) {
        for (var environment : FCEnvironment.values()) {
            if (environment.name().equalsIgnoreCase(environmentName)) {
                return environment;
            }
        }

        return defaultEnvironment;
    }
}
