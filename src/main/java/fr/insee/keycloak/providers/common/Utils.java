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

  // We need this due to a bug in signature verification
  // (https://github.com/GluuFederation/oxAuth/issues/1210)
  public static byte[] transcodeSignatureToDER(byte[] jwsSignature) {

    // Adapted from
    // org.apache.xml.security.algorithms.implementations.SignatureECDSA

    int rawLen = jwsSignature.length / 2;

    int i;

    for (i = rawLen; (i > 0) && (jwsSignature[rawLen - i] == 0); i--) {
      // do nothing
    }

    int j = i;

    if (jwsSignature[rawLen - i] < 0) {
      j += 1;
    }

    int k;

    for (k = rawLen; (k > 0) && (jwsSignature[2 * rawLen - k] == 0); k--) {
      // do nothing
    }

    int l = k;

    if (jwsSignature[2 * rawLen - k] < 0) {
      l += 1;
    }

    int len = 2 + j + 2 + l;

    if (len > 255) {
      throw new RuntimeException("Invalid ECDSA signature format");
    }

    int offset;

    final byte derSignature[];

    if (len < 128) {
      derSignature = new byte[2 + 2 + j + 2 + l];
      offset = 1;
    } else {
      derSignature = new byte[3 + 2 + j + 2 + l];
      derSignature[1] = (byte) 0x81;
      offset = 2;
    }

    derSignature[0] = 48;
    derSignature[offset++] = (byte) len;
    derSignature[offset++] = 2;
    derSignature[offset++] = (byte) j;

    System.arraycopy(jwsSignature, rawLen - i, derSignature, (offset + j) - i, i);

    offset += j;

    derSignature[offset++] = 2;
    derSignature[offset++] = (byte) l;

    System.arraycopy(jwsSignature, 2 * rawLen - k, derSignature, (offset + l) - k, k);

    return derSignature;
  }

  public static byte[] generateRandomBytes(int length) {
    if (length < 1) {
      throw new IllegalArgumentException();
    }

    byte[] buf = new byte[length];
    random.get().nextBytes(buf);
    return buf;
  }
}
