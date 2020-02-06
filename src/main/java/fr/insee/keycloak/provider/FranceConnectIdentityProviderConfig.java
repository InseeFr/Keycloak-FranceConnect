package fr.insee.keycloak.provider;

import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.models.IdentityProviderModel;

class FranceConnectIdentityProviderConfig extends OIDCIdentityProviderConfig {

    FranceConnectIdentityProviderConfig(IdentityProviderModel identityProviderModel) {
        super(identityProviderModel);

        initialize();
    }

    private void initialize() {
        Environment franceConnectEnvironment = Environment.getOrDefault(
            getConfig().get(Environment.ENVIRONMENT_PROPERTY_NAME),
            Environment.INTEGRATION
        );

        franceConnectEnvironment.configureUrls(this);

        this.setValidateSignature(true);
        this.setBackchannelSupported(false);
    }

    boolean isIgnoreAbsentStateParameterLogout() {
        return Boolean.parseBoolean(getConfig().get("ignoreAbsentStateParameterLogout"));
    }

    String getAcrValues() {
        return EidasLevel.getOrDefault(
            getConfig().get(EidasLevel.EIDAS_LEVEL_PROPERTY_NAME),
            EidasLevel.EIDAS1
        ).toString();
    }

    enum EidasLevel {

        EIDAS1, EIDAS2, EIDAS3;

        static final String EIDAS_LEVEL_PROPERTY_NAME = "acr_values";

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
        INTEGRATION(
            "https://fcp.integ01.dev-franceconnect.fr/api/v1/authorize",
                "https://fcp.integ01.dev-franceconnect.fr/api/v1/token",
                "https://fcp.integ01.dev-franceconnect.fr/api/v1/userinfo",
                "https://fcp.integ01.dev-franceconnect.fr/api/v1/logout"
        ),
        PRODUCTION(
                "https://app.franceconnect.gouv.fr/api/v1/authorize",
                "https://app.franceconnect.gouv.fr/api/v1/token",
                "https://app.franceconnect.gouv.fr/api/v1/userinfo",
                "https://app.franceconnect.gouv.fr/api/v1/logout"
        );

        static final String ENVIRONMENT_PROPERTY_NAME = "fc_environment";

        private final String authorizationUrl;
        private final String tokenUrl;
        private final String userInfoUrl;
        private final String logoutUrl;

        Environment(String authorizationUrl, String tokenUrl, String userInfoUrl, String logoutUrl) {
            this.authorizationUrl = authorizationUrl;
            this.tokenUrl = tokenUrl;
            this.userInfoUrl = userInfoUrl;
            this.logoutUrl = logoutUrl;
        }

        void configureUrls(OIDCIdentityProviderConfig config) {
            config.setAuthorizationUrl(authorizationUrl);
            config.setTokenUrl(tokenUrl);
            config.setUserInfoUrl(userInfoUrl);
            config.setLogoutUrl(logoutUrl);
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

