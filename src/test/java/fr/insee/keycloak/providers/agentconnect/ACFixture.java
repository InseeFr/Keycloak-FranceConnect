package fr.insee.keycloak.providers.agentconnect;

import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import fr.insee.keycloak.providers.common.EidasLevel;
import fr.insee.keycloak.utils.SignatureUtils;
import org.keycloak.models.IdentityProviderModel;

import static fr.insee.keycloak.utils.KeycloakFixture.CLIENT_ID;
import static fr.insee.keycloak.utils.KeycloakFixture.CLIENT_SECRET;
import static fr.insee.keycloak.utils.SignatureUtils.generateRSA256Key;
import static fr.insee.keycloak.utils.SignatureUtils.signJwtWithRSA256PrivateKey;

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

  static final JWTClaimsSet EIDAS3_JWT = new JWTClaimsSet.Builder()
      .subject("fakeSub")
      .issuer("https://fca.integ02.agentconnect.rie.gouv.fr/api/v2")
      .audience(CLIENT_ID)
      .claim("nonce", "randomNonce")
      .claim("idp", "AC")
      .claim("acr", "eidas3")
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

  static final JWTClaimsSet EIDAS0_MFA_JWT = new JWTClaimsSet.Builder()
      .subject("fakeSub")
      .issuer("https://fca.integ02.agentconnect.rie.gouv.fr/api/v2")
      .audience(CLIENT_ID)
      .claim("nonce", "randomNonce")
      .claim("idp", "AC")
      .claim("acr", "eidas0-mfa")
      .claim("amr", null)
      .build();

  static final JWTClaimsSet EIDAS1_MFA_JWT = new JWTClaimsSet.Builder()
      .subject("fakeSub")
      .issuer("https://fca.integ02.agentconnect.rie.gouv.fr/api/v2")
      .audience(CLIENT_ID)
      .claim("nonce", "randomNonce")
      .claim("idp", "AC")
      .claim("acr", "eidas1-mfa")
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

    var config = new AgentConnectIdentityProviderConfig(model);
    config.setEnabled(true);

    return config;
  }

  static AgentConnectIdentityProviderConfig givenConfigWithEidas0MfaEnabled() {
    return givenConfigWithMfaRequirementAndEidasLevel(MfaRequirement.REQUIRED, EidasLevel.EIDAS0.toString());
  }

  static AgentConnectIdentityProviderConfig givenConfigWithEidas1MfaEnabled() {
    return givenConfigWithMfaRequirementAndEidasLevel(MfaRequirement.REQUIRED, EidasLevel.EIDAS1.toString());
  }

  static AgentConnectIdentityProviderConfig givenConfigWithMfaEnabledAndEidasLevel(String eidasLevelName) {
    return givenConfigWithMfaRequirementAndEidasLevel(MfaRequirement.REQUIRED, eidasLevelName);
  }

  static AgentConnectIdentityProviderConfig givenConfigWithMfaRequirementAndEidasLevel(
      MfaRequirement mfaRequirement, String eidasLevelName) {
    var model = new IdentityProviderModel();
    model.getConfig().put(ACEnvironment.ENVIRONMENT_PROPERTY_NAME, "integration_rie");
    model.getConfig().put(MfaRequirement.MFA_MODE_PROPERTY_NAME, mfaRequirement.name());
    model.getConfig().put(EidasLevel.EIDAS_LEVEL_PROPERTY_NAME, eidasLevelName);
    model.getConfig().put("ignoreAbsentStateParameterLogout", "false");
    model.getConfig().put("clientId", CLIENT_ID);
    model.getConfig().put("clientSecret", CLIENT_SECRET);

    return new AgentConnectIdentityProviderConfig(model);
  }

  static AgentConnectIdentityProviderConfig givenConfigWithLegacyMfaEnabled(String legacyMfaEnabledValue) {
    var model = new IdentityProviderModel();
    model.getConfig().put(ACEnvironment.ENVIRONMENT_PROPERTY_NAME, "integration_rie");
    model.getConfig().put(AgentConnectIdentityProviderConfig.LEGACY_MFA_ENABLED_PROPERTY_NAME, legacyMfaEnabledValue);
    model.getConfig().put(EidasLevel.EIDAS_LEVEL_PROPERTY_NAME, EidasLevel.EIDAS1.toString());
    model.getConfig().put("ignoreAbsentStateParameterLogout", "false");
    model.getConfig().put("clientId", CLIENT_ID);
    model.getConfig().put("clientSecret", CLIENT_SECRET);

    return new AgentConnectIdentityProviderConfig(model);
  }

  static String givenAnRSASignedJWTWithUnknownKidInJWKS() {
    var rsaKey = generateRSA256Key("unknownKid");
    return signJwtWithRSA256PrivateKey(EIDAS2_JWT, rsaKey);
  }

  static String givenAnRSASignedEidas2JWTWithRegisteredKidInJWKS(RSAKey rsaKey) {
    return SignatureUtils.givenAnRSASignedJWTWithRegisteredKidInJWKS(rsaKey, EIDAS2_JWT);
  }

  static String givenAnECDSASignedEidas2JWTWithRegisteredKidInJWKS(ECKey ecKey) {
    return SignatureUtils.givenAnECDSASignedJWTWithRegisteredKidInJWKS(ecKey, EIDAS2_JWT);
  }
}
