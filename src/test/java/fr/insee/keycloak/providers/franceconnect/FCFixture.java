package fr.insee.keycloak.providers.franceconnect;

import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import fr.insee.keycloak.providers.common.EidasLevel;
import fr.insee.keycloak.utils.SignatureUtils;
import org.keycloak.models.IdentityProviderModel;

import static fr.insee.keycloak.utils.KeycloakFixture.CLIENT_ID;
import static fr.insee.keycloak.utils.KeycloakFixture.CLIENT_SECRET;
import static fr.insee.keycloak.utils.SignatureUtils.*;

final class FCFixture {

  private FCFixture() {
  }

  static final JWTClaimsSet EIDAS1_JWT = new JWTClaimsSet.Builder()
      .subject("fakeSub")
      .issuer("https://fcp-low.sbx.dev-franceconnect.fr/api/v2")
      .audience(CLIENT_ID)
      .claim("nonce", "randomNonce")
      .claim("idp", "FC")
      .claim("acr", "eidas1")
      .claim("amr", null)
      .build();

  static final JWTClaimsSet EIDAS2_JWT = new JWTClaimsSet.Builder()
      .subject("fakeSub")
      .issuer("https://auth.integ01.dev-franceconnect.fr/api/v2")
      .audience(CLIENT_ID)
      .claim("nonce", "randomNonce")
      .claim("idp", "FC")
      .claim("acr", "eidas2")
      .claim("amr", null)
      .build();

  static final JWTClaimsSet NO_EIDAS_LEVEL_JWT = new JWTClaimsSet.Builder()
      .subject("fakeSub")
      .issuer("https://auth.integ01.dev-franceconnect.fr/api/v2")
      .audience(CLIENT_ID)
      .claim("nonce", "randomNonce")
      .claim("idp", "FC")
      .claim("amr", null)
      .build();

  static final JWTClaimsSet UNSUPPORTED_EIDAS_LEVEL_JWT = new JWTClaimsSet.Builder()
      .subject("fakeSub")
      .issuer("https://auth.integ01.dev-franceconnect.fr/api/v2")
      .audience(CLIENT_ID)
      .claim("nonce", "randomNonce")
      .claim("idp", "FC")
      .claim("acr", "eidas99")
      .claim("amr", null)
      .build();

  static final JWTClaimsSet USERINFO_JWT = new JWTClaimsSet.Builder()
      .claim("sub", "fakeSub")
      .claim("given_name", "John")
      .claim("family_name", "Doe")
      .claim("email", "john.doe@gmail.com")
      .build();

  static FranceConnectIdentityProviderConfig givenConfigForIntegrationAndEidasLevel1() {
    return givenConfigWithSelectedEnvAndSelectedEidasLevel("integration_standard_v2", "eidas1");
  }

  static FranceConnectIdentityProviderConfig givenConfigForIntegrationPlusAndEidasLevel2() {
    return givenConfigWithSelectedEnvAndSelectedEidasLevel("integration_plus_v2", "eidas2");
  }

  static FranceConnectIdentityProviderConfig givenConfigWithSelectedEnvAndSelectedEidasLevel(String environmentName, String eidasLevelName) {
    var model = new IdentityProviderModel();
    model.getConfig().put(FCEnvironment.ENVIRONMENT_PROPERTY_NAME, environmentName);
    model.getConfig().put(EidasLevel.EIDAS_LEVEL_PROPERTY_NAME, eidasLevelName);
    model.getConfig().put("ignoreAbsentStateParameterLogout", "false");
    model.getConfig().put("clientId", CLIENT_ID);
    model.getConfig().put("clientSecret", CLIENT_SECRET);

    var config = new FranceConnectIdentityProviderConfig(model);
    config.setEnabled(true);

    return config;
  }

  static String givenAnRSASignedEidas1JWT(RSAKey rsaKey) {
    return givenAnRSASignedJWTWithRegisteredKidInJWKS(rsaKey, EIDAS1_JWT);
  }

  static String givenAnRSAOAEPJWEForAnECDSASignedEidas2JWTWithRegisteredKidInJWKS(ECKey ecKey, RSAKey rsaKey) {
    return SignatureUtils.givenAnRSAOAEPJWE(
        rsaKey,
        SignatureUtils.givenAnECDSASignedJWTWithRegisteredKidInJWKS(ecKey, EIDAS2_JWT)
    );
  }

  static String givenAnES256SignedJWTWithUnknownKidInJWKS() {
    var ecKey = generateES256Key("unknownKid");
    return signJwtWithES256PrivateKey(EIDAS2_JWT, ecKey);
  }
}
