package fr.insee.keycloak.provider;

import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.models.IdentityProviderModel;

class FranceConnectIdentityProviderConfig extends OIDCIdentityProviderConfig {

    private static final EidasLevel DEFAULT_EIDAS_LEVEL = EidasLevel.EIDAS1;
    private static final Environment DEFAULT_FC_ENVIRONMENT = Environment.INTEGRATION;

    FranceConnectIdentityProviderConfig(IdentityProviderModel identityProviderModel) {
        super(identityProviderModel);

        initialize();
    }

    FranceConnectIdentityProviderConfig() {
        super();
        initialize();
    }

    private void initialize() {
        Environment franceConnectEnvironment = Environment.getOrDefault(
            getConfig().get(Environment.ENVIRONMENT_PROPERTY_NAME),
            DEFAULT_FC_ENVIRONMENT
        );

        franceConnectEnvironment.configureUrls(this);

        this.setValidateSignature(true);
        this.setBackchannelSupported(false);
    }

    boolean isIgnoreAbsentStateParameterLogout() {
        return Boolean.parseBoolean(
            getConfig().get("ignoreAbsentStateParameterLogout")
        );
    }

    EidasLevel getEidasLevel() {
        return EidasLevel.getOrDefault(
            getConfig().get(EidasLevel.EIDAS_LEVEL_PROPERTY_NAME),
            DEFAULT_EIDAS_LEVEL
        );
    }

    enum EidasLevel {

        EIDAS1, EIDAS2, EIDAS3;

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

        INTEGRATION("https://fcp.integ01.dev-franceconnect.fr/api/v1"),
        PRODUCTION("https://app.franceconnect.gouv.fr/api/v1");

        static final String ENVIRONMENT_PROPERTY_NAME = "fc_environment";

        private final String baseUrl;

        Environment(String baseUrl) {
            this.baseUrl = baseUrl;
        }

        void configureUrls(OIDCIdentityProviderConfig config) {
            config.setAuthorizationUrl(baseUrl + "/authorize");
            config.setTokenUrl(baseUrl + "/token");
            config.setUserInfoUrl(baseUrl + "/userinfo");
            config.setLogoutUrl(baseUrl + "/logout");
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

