package fr.insee.keycloak.utils;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.util.Map;

import static fr.insee.keycloak.utils.TestUtils.mapToJsonFormat;

public final class SignatureUtils {

  private SignatureUtils() {
  }

  public static String signJwtWithHS256SharedSecret(JWTClaimsSet claimsSet, String sharedSecret) {
    try {
      var signer = new MACSigner(sharedSecret);
      var signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);

      signedJWT.sign(signer);

      return signedJWT.serialize();
    } catch (JOSEException ex) {
      throw new IllegalStateException(ex);
    }
  }

  public static String givenAnRSASignedJWTWithRegisteredKidInJWKS(String kid, JWTClaimsSet claimsSet, PublicKeysStore publicKeysStore) {
    var rsaKey = generateRSA256Key(kid);
    var publicKey = generateRSA256PublicKeyInJsonFormat(rsaKey);

    publicKeysStore.add(publicKey);

    return signJwtWithRSA256PrivateKey(claimsSet, rsaKey);
  }

  public static String givenAnECDSASignedJWTWithRegisteredKidInJWKS(String kid, JWTClaimsSet claimsSet, PublicKeysStore publicKeysStore) {
    var ecKey = generateES256Key(kid);
    var publicKey = generateES256PublicKeyInJsonFormat(ecKey);

    publicKeysStore.add(publicKey);

    return signJwtWithES256PrivateKey(claimsSet, ecKey);
  }

  public static String givenAnRSAOAEPJWE(RSAKey rsaKey, String signedJwt) {
    var cek = generateHS256ContentEncryptionKey();

    return createJWEWithRSAOAEP256Algorithm(signedJwt, rsaKey, cek);
  }

  public static RSAKey generateRSA256Key(String kid) {
    try {
      return new RSAKeyGenerator(2048)
          .keyID(kid)
          .keyUse(KeyUse.SIGNATURE)
          .algorithm(JWSAlgorithm.RS256)
          .generate();
    } catch (JOSEException ex) {
      throw new IllegalStateException(ex);
    }
  }

  public static String signJwtWithRSA256PrivateKey(JWTClaimsSet claimsSet, RSAKey rsaKey) {
    try {
      var signer = new RSASSASigner(rsaKey);
      var signedJWT = new SignedJWT(
          new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaKey.getKeyID()).build(),
          claimsSet
      );

      signedJWT.sign(signer);

      return signedJWT.serialize();
    } catch (JOSEException ex) {
      throw new IllegalStateException(ex);
    }
  }

  public static String generateRSA256PublicKeyInJsonFormat(RSAKey rsaKey) {

    try {
      var jsonObject = rsaKey.toPublicJWK().toJSONObject();
      return new ObjectMapper().writeValueAsString(jsonObject);
    } catch (JsonProcessingException ex) {
      throw new IllegalStateException(ex);
    }
  }

  public static ECKey generateES256Key(String kid) {
    try {
      return new ECKeyGenerator(Curve.P_256)
          .keyID(kid)
          .keyUse(KeyUse.SIGNATURE)
          .algorithm(JWSAlgorithm.ES256)
          .generate();
    } catch (JOSEException ex) {
      throw new IllegalStateException(ex);
    }
  }

  public static String signJwtWithES256PrivateKey(JWTClaimsSet claimsSet, ECKey ecKey) {
    try {
      var signer = new ECDSASigner(ecKey);
      var signedJWT = new SignedJWT(
          new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(ecKey.getKeyID()).build(),
          claimsSet
      );

      signedJWT.sign(signer);

      return signedJWT.serialize();
    } catch (JOSEException ex) {
      throw new IllegalStateException(ex);
    }
  }

  public static String generateES256PublicKeyInJsonFormat(ECKey ecKey) {
    try {
      var jsonObject = ecKey.toPublicJWK().toJSONObject();
      return new ObjectMapper().writeValueAsString(jsonObject);
    } catch (JsonProcessingException ex) {
      throw new IllegalStateException(ex);
    }
  }

  public static SecretKey generateHS256ContentEncryptionKey() {
    try {
      var keyGenerator = KeyGenerator.getInstance("AES");
      keyGenerator.init(EncryptionMethod.A128CBC_HS256.cekBitLength());
      return keyGenerator.generateKey();
    } catch (NoSuchAlgorithmException ex) {
      throw new IllegalStateException(ex);
    }
  }

  public static String createJWEWithRSAOAEP256Algorithm(String signedJwt, RSAKey rsaKey, SecretKey cek) {
    try {
      var jwe = new JWEObject(
          new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128CBC_HS256).keyID(rsaKey.getKeyID()).build(),
          new Payload(signedJwt)
      );

      jwe.encrypt(new RSAEncrypter(rsaKey.toRSAPublicKey(), cek));
      return jwe.serialize();
    } catch (JOSEException ex) {
      throw new IllegalStateException(ex);
    }
  }

  public static String generateTokenEndpointResponse(String accessToken, String idToken) {
    var endpointResponseMap = Map.of(
        "access_token", accessToken,
        "token_type", "Bearer",
        "expires_in", "60",
        "id_token", idToken
    );

    return mapToJsonFormat(endpointResponseMap);
  }
}
