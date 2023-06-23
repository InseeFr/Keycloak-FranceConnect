package fr.insee.keycloak.providers.franceconnect;

import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import fr.insee.keycloak.providers.common.EidasLevel;
import fr.insee.keycloak.utils.PublicKeysStore;
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
      .issuer("https://auth.integ01.dev-franceconnect.fr/api/v2")
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

  static FranceConnectIdentityProviderConfig givenConfigWithSelectedEnv(FCEnvironment fcEnvironment) {
    var model = new IdentityProviderModel();
    //model.getConfig().put("ignoreAbsentStateParameterLogout", "false");
    model.getConfig().put("clientId", CLIENT_ID);
    model.getConfig().put("clientSecret", CLIENT_SECRET);

    return new FranceConnectIdentityProviderConfig(model,fcEnvironment,"provider-id");
  }

  static String givenAnHMACSignedEidas1JWT() {
    return signJwtWithHS256SharedSecret(EIDAS1_JWT, CLIENT_SECRET);
  }

  static String givenAnRSAOAEPJWEForAnECDSASignedEidas2JWTWithRegisteredKidInJWKS(String kid, PublicKeysStore publicKeysStore, RSAKey rsaKey) {
    return SignatureUtils.givenAnRSAOAEPJWE(
        rsaKey,
        SignatureUtils.givenAnECDSASignedJWTWithRegisteredKidInJWKS(kid, EIDAS2_JWT, publicKeysStore)
    );
  }

  static String givenAnES256SignedJWTWithUnknownKidInJWKS() {
    var ecKey = generateES256Key("unknownKid");
    return signJwtWithES256PrivateKey(EIDAS2_JWT, ecKey);
  }
}
