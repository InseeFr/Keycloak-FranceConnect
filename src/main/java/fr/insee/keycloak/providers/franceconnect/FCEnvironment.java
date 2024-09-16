package fr.insee.keycloak.providers.franceconnect;

import fr.insee.keycloak.providers.common.Utils;

import java.util.Properties;

enum FCEnvironment {
  // Legacy V1 , should stop in 2025
  INTEGRATION_V1("france-connect.integration.v1"),
  PRODUCTION_V1("france-connect.production.v1"),
  // Names left for retro compatibility, prefer now "Plus"
  INTEGRATION_V2("france-connect.plus.integration.v2"),
  PRODUCTION_V2("france-connect.plus.production.v2"),
  // FranceConnect V2, called standard in this project to differentiate with "Plus"
  INTEGRATION_STANDARD_V2("france-connect.standard.integration.v2"),
  PRODUCTION_STANDARD_V2("france-connect.standard.production.v2"),
  // FranceConnect Plus V2
  INTEGRATION_PLUS_V2("france-connect.plus.integration.v2"),
  PRODUCTION_PLUS_V2("france-connect.plus.production.v2");

  static final String ENVIRONMENT_PROPERTY_NAME = "fc_environment";
  private static final Properties PROPERTIES = Utils.loadProperties("france-connect.properties");

  private final String propertyPrefix;

  FCEnvironment(String propertyPrefix) {
    this.propertyPrefix = propertyPrefix;
  }

  public String getProperty(String key) {
    return PROPERTIES.getProperty(propertyPrefix + "." + key);
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
