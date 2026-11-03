package fr.insee.keycloak.providers.common;

import fr.insee.keycloak.mappers.FranceConnectUserAttributeMapper;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Properties;
import java.util.Random;
import org.jboss.logging.Logger;
import org.keycloak.broker.oidc.mappers.AbstractClaimMapper;
import org.keycloak.broker.oidc.mappers.UserAttributeMapper;
import org.keycloak.broker.provider.HardcodedAttributeMapper;
import org.keycloak.jose.jwk.JSONWebKeySet;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.IdentityProviderMapperSyncMode;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.utils.JWKSHttpUtils;

public final class Utils {

  private static final Logger logger = Logger.getLogger(Utils.class);

  private static ThreadLocal<Random> random = ThreadLocal.withInitial(() -> new SecureRandom());

  private Utils() {}

  public static IdentityProviderMapperModel createUserAttributeMapper(
      String providerId, String mapperName, String claimAttributeName, String userAttributeName) {
    var mapper = new IdentityProviderMapperModel();

    mapper.setName(mapperName);
    mapper.setIdentityProviderMapper(FranceConnectUserAttributeMapper.MAPPER_NAME);
    mapper.setIdentityProviderAlias(providerId);
    mapper.setConfig(new HashMap<>());
    mapper.setSyncMode(IdentityProviderMapperSyncMode.INHERIT);
    mapper.getConfig().put(AbstractClaimMapper.CLAIM, claimAttributeName);
    mapper.getConfig().put(UserAttributeMapper.USER_ATTRIBUTE, userAttributeName);

    return mapper;
  }

  public static IdentityProviderMapperModel createHardcodedAttributeMapper(
      String providerId, String mapperName, String attributeName, String attributeValue) {

    var mapper = new IdentityProviderMapperModel();

    mapper.setName(mapperName);
    mapper.setIdentityProviderMapper(HardcodedAttributeMapper.PROVIDER_ID);
    mapper.setIdentityProviderAlias(providerId);
    mapper.setConfig(new HashMap<>());
    mapper.setSyncMode(IdentityProviderMapperSyncMode.INHERIT);
    mapper.getConfig().put(HardcodedAttributeMapper.ATTRIBUTE, attributeName);
    mapper.getConfig().put(HardcodedAttributeMapper.ATTRIBUTE_VALUE, attributeValue);

    return mapper;
  }

  public static Properties loadProperties(String propertiesFile) {
    var properties = new Properties();
    try (var stream = Utils.class.getClassLoader().getResourceAsStream(propertiesFile)) {
      properties.load(stream);
      return properties;
    } catch (IOException ex) {
      throw new IllegalStateException("Cannot load properties from file " + propertiesFile, ex);
    }
  }

  public static JSONWebKeySet getJsonWebKeySetFrom(String jwksUrl, KeycloakSession session) {
    try {
      return JWKSHttpUtils.sendJwksRequest(session, jwksUrl);
    } catch (IOException ex) {
      logger.warn("Error when fetching keys on JWKS URL: " + jwksUrl, ex);
      throw new IllegalStateException(ex);
    }
  }

}
