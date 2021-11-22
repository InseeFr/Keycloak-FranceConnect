package fr.insee.keycloak.providers.agentconnect;

import fr.insee.keycloak.providers.common.Utils;

import java.util.Properties;

enum ACEnvironment {

  INTEGRATION_RIE("agent-connect.integration.rie"),
  PRODUCTION_RIE("agent-connect.production.rie"),
  INTEGRATION_INTERNET("agent-connect.integration.internet"),
  PRODUCTION_INTERNET("agent-connect.production.internet");

  static final String ENVIRONMENT_PROPERTY_NAME = "fc_environment";
  private static final Properties PROPERTIES = Utils.loadProperties("agent-connect.properties");

  private final String propertyPrefix;

  ACEnvironment(String propertyPrefix) {
    this.propertyPrefix = propertyPrefix;
  }

  public String getProperty(String key) {
    return PROPERTIES.getProperty(propertyPrefix + "." + key);
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
