package fr.insee.keycloak.providers.common;

import org.jboss.logging.Logger;
import org.keycloak.jose.jwk.JSONWebKeySet;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.utils.JWKSHttpUtils;

import java.io.IOException;

public final class Utils {

  private static final Logger logger = Logger.getLogger(Utils.class);

  private Utils() {
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
}
