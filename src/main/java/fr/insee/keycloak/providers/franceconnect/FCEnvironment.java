package fr.insee.keycloak.providers.franceconnect;

import fr.insee.keycloak.providers.common.Environment;
import fr.insee.keycloak.providers.common.Utils;

import java.util.Properties;

enum FCEnvironment implements Environment {

  INTEGRATION_V1("france-connect.integration.v1"),
  PRODUCTION_V1("france-connect.production.v1"),
  INTEGRATION_V2("france-connect.integration.v2"),
  PRODUCTION_V2("france-connect.production.v2");

  private static final Properties PROPERTIES = Utils.loadProperties("france-connect.properties");

  private final String propertyPrefix;

  FCEnvironment(String propertyPrefix) {
    this.propertyPrefix = propertyPrefix;
  }

  @Override
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
