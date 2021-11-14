package fr.insee.keycloak.providers.agentconnect;

import com.nimbusds.jwt.JWTClaimsSet;
import fr.insee.keycloak.providers.common.EidasLevel;
import fr.insee.keycloak.utils.PublicKeysStore;
import fr.insee.keycloak.utils.SignatureUtils;
import org.keycloak.models.IdentityProviderModel;

import static fr.insee.keycloak.utils.KeycloakFixture.CLIENT_ID;
import static fr.insee.keycloak.utils.KeycloakFixture.CLIENT_SECRET;
import static fr.insee.keycloak.utils.SignatureUtils.*;

final class ACFixture {

  static final JWTClaimsSet EIDAS1_JWT = new JWTClaimsSet.Builder()
      .subject("fakeSub")
      .issuer("https://fca.integ02.agentconnect.rie.gouv.fr/api/v2")
      .audience(CLIENT_ID)
      .claim("nonce", "randomNonce")
      .claim("idp", "AC")
      .claim("acr", "eidas1")
      .claim("amr", null)
      .build();

  static final JWTClaimsSet EIDAS2_JWT = new JWTClaimsSet.Builder()
      .subject("fakeSub")
      .issuer("https://fca.integ02.agentconnect.rie.gouv.fr/api/v2")
      .audience(CLIENT_ID)
      .claim("nonce", "randomNonce")
      .claim("idp", "AC")
      .claim("acr", "eidas2")
      .claim("amr", null)
      .build();

  static final JWTClaimsSet NO_EIDAS_LEVEL_JWT = new JWTClaimsSet.Builder()
      .subject("fakeSub")
      .issuer("https://fca.integ02.agentconnect.rie.gouv.fr/api/v2")
      .audience(CLIENT_ID)
      .claim("nonce", "randomNonce")
      .claim("idp", "AC")
      .claim("amr", null)
      .build();

  static final JWTClaimsSet UNSUPPORTED_EIDAS_LEVEL_JWT = new JWTClaimsSet.Builder()
      .subject("fakeSub")
      .issuer("https://fca.integ02.agentconnect.rie.gouv.fr/api/v2")
      .audience(CLIENT_ID)
      .claim("nonce", "randomNonce")
      .claim("idp", "AC")
      .claim("acr", "eidas99")
      .claim("amr", null)
      .build();

  static final JWTClaimsSet USERINFO_JWT = new JWTClaimsSet.Builder()
      .claim("sub", "fakeSub")
      .claim("given_name", "John")
      .claim("family_name", "Doe")
      .claim("email", "john.doe@gmail.com")
      .build();

  private ACFixture() {
  }

  static AgentConnectIdentityProviderConfig givenConfigForIntegrationAndEidasLevel2() {
    return givenConfigWithSelectedEnvAndSelectedEidasLevel("integration_rie", "eidas2");
  }

  static AgentConnectIdentityProviderConfig givenConfigWithSelectedEnvAndSelectedEidasLevel(String environmentName, String eidasLevelName) {
    var model = new IdentityProviderModel();
    model.getConfig().put(ACEnvironment.ENVIRONMENT_PROPERTY_NAME, environmentName);
    model.getConfig().put(EidasLevel.EIDAS_LEVEL_PROPERTY_NAME, eidasLevelName);
    model.getConfig().put("ignoreAbsentStateParameterLogout", "false");
    model.getConfig().put("clientId", CLIENT_ID);
    model.getConfig().put("clientSecret", CLIENT_SECRET);

    return new AgentConnectIdentityProviderConfig(model);
  }

  static String givenAnHMACSignedEidas2JWT() {
    return signJwtWithHS256SharedSecret(EIDAS2_JWT, CLIENT_SECRET);
  }

  static String givenAnRSASignedJWTWithUnknownKidInJWKS() {
    var rsaKey = generateRSA256Key("unknownKid");
    return signJwtWithRSA256PrivateKey(EIDAS2_JWT, rsaKey);
  }

  static String givenAnRSASignedEidas2JWTWithRegisteredKidInJWKS(String kid, PublicKeysStore publicKeysStore) {
    return SignatureUtils.givenAnRSASignedJWTWithRegisteredKidInJWKS(kid, EIDAS2_JWT, publicKeysStore);
  }

  static String givenAnECDSASignedEidas2JWTWithRegisteredKidInJWKS(String kid, PublicKeysStore publicKeysStore) {
    return SignatureUtils.givenAnECDSASignedJWTWithRegisteredKidInJWKS(kid, EIDAS2_JWT, publicKeysStore);
  }
}
