package fr.insee.keycloak.providers.franceconnect;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.RSAKey;
import fr.insee.keycloak.providers.common.EidasLevel;
import fr.insee.keycloak.utils.ClosableHttpResponse;
import fr.insee.keycloak.utils.KeycloakFixture;
import fr.insee.keycloak.utils.SignatureUtils;
import fr.insee.keycloak.utils.TestUtils;
import jakarta.ws.rs.core.HttpHeaders;
import org.apache.http.impl.client.CloseableHttpClient;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator.ReplaceUnderscores;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.crypto.*;
import org.keycloak.keys.PublicKeyStorageProvider;
import org.keycloak.models.*;
import org.keycloak.representations.JsonWebToken;

import java.io.IOException;
import java.text.ParseException;
import java.util.Map;

import static fr.insee.keycloak.providers.franceconnect.FCFixture.*;
import static fr.insee.keycloak.utils.KeycloakFixture.givenAuthenticationRequest;
import static fr.insee.keycloak.utils.SignatureUtils.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.keycloak.broker.oidc.OIDCIdentityProvider.VALIDATED_ID_TOKEN;
import static org.mockito.Mockito.*;

@DisplayNameGeneration(ReplaceUnderscores.class)
class FranceConnectIdentityProviderTest {

  private KeycloakSession session;

  @BeforeEach
  void setup() {
    session=mock(KeycloakSession.class);
  }

  @Test
  void should_load_jwks_from_jwks_url_when_configuration_supports_jwks() {
    var config = givenConfigForIntegrationAndEidasLevel1();
    var provider = new FranceConnectIdentityProvider(session, config);

    assertThat(provider.getConfig().isValidateSignature()).isTrue();
    assertThat(provider.getConfig().isUseJwksUrl()).isTrue();
    assertThat(provider.getConfig().getJwksUrl()).isNotEmpty();
  }

  @Nested
  class AuthorizationUrlCreation {

    @Test
    void should_create_authorization_url_with_eidas_level_as_acr_values_query_param() {
      var config = givenConfigForIntegrationPlusAndEidasLevel2();
      var provider = new FranceConnectIdentityProvider(session, config);
      var request = givenAuthenticationRequest(session);

      var authorizationUrl = provider.createAuthorizationUrl(request).build();
      var queryParams = TestUtils.uriQueryStringToMap(authorizationUrl);

      assertThat(authorizationUrl.toString()).startsWith(config.getAuthorizationUrl());
      assertThat(queryParams)
          .containsEntry("acr_values", EidasLevel.EIDAS2.toString())
          .containsEntry("scope", KeycloakFixture.DEFAULT_SCOPE)
          .containsEntry("response_type", "code")
          .containsEntry("state", KeycloakFixture.STATE_VALUE)
          .containsEntry("client_id", KeycloakFixture.CLIENT_ID)
          .containsEntry("redirect_uri", KeycloakFixture.REDIRECT_URI)
          .containsKey("nonce");
    }

    @Test
    void should_create_authorization_url_with_nonce_query_param_having_at_least_22_chars() {
      var config = givenConfigForIntegrationAndEidasLevel1();
      var provider = new FranceConnectIdentityProvider(session, config);
      var request = givenAuthenticationRequest(session);

      var authorizationUrl = provider.createAuthorizationUrl(request).build();
      var queryParams = TestUtils.uriQueryStringToMap(authorizationUrl);

      assertThat(authorizationUrl.toString()).startsWith(config.getAuthorizationUrl());
      // france connect requires nonce size to be at least 22
      assertThat(queryParams).hasEntrySatisfying("nonce", value -> assertThat(value).hasSizeGreaterThanOrEqualTo(22));
    }
  }

  @Nested
  class IdTokenValidation {

    // Used to sign JWT
    private RSAKey rsaKeySign;

    // Used to sign JWT
    private ECKey ecKeySign;

    // Used to create JWE (public key) and to decrypt JWE (private key)
    private RSAKey rsaKeyJWEEncryption;

    @BeforeEach
    void setup() throws JOSEException {

      var asymmetricSignatureProvider = new AsymmetricSignatureProvider(session,"RS256");
      when(session.getProvider(SignatureProvider.class,"RS256")).thenReturn(asymmetricSignatureProvider);

      var eCDSASignatureProvider = new ECDSASignatureProvider(session,"ES256");
      when(session.getProvider(SignatureProvider.class,"ES256")).thenReturn(eCDSASignatureProvider);

      // Prepare RSA and EC signature

      rsaKeySign = generateRSA256Key("RSA_KID");
      var keyWrapperRSASignature = new KeyWrapper();
      keyWrapperRSASignature.setKid(rsaKeySign.getKeyID());
      keyWrapperRSASignature.setPublicKey(rsaKeySign.toPublicKey());
      keyWrapperRSASignature.setType(KeyType.RSA);

      ecKeySign = generateES256Key("ECDSA-KID");
      var keyWrapperECSignature = new KeyWrapper();
      keyWrapperECSignature.setKid(ecKeySign.getKeyID());
      keyWrapperECSignature.setPublicKey(ecKeySign.toPublicKey());
      keyWrapperECSignature.setType(KeyType.EC);;


      var publicKeyStorageProvider = mock((PublicKeyStorageProvider.class));
      when(session.getProvider(PublicKeyStorageProvider.class)).thenReturn(publicKeyStorageProvider);
      when(publicKeyStorageProvider.getPublicKey(any(),eq("RSA_KID"),eq("RS256"),any())).thenReturn(keyWrapperRSASignature);
      when(publicKeyStorageProvider.getPublicKey(any(),eq("ECDSA-KID"),eq("ES256"),any())).thenReturn(keyWrapperECSignature);

      // Prepare JWE encryption
      rsaKeyJWEEncryption = generateRSA256Key("RSA-OEAP-KID");
      var keyWrapperJWEEncryption = new KeyWrapper();
      keyWrapperJWEEncryption.setKid(rsaKeyJWEEncryption.getKeyID());
      keyWrapperJWEEncryption.setPublicKey(rsaKeyJWEEncryption.toPublicKey());
      keyWrapperJWEEncryption.setPrivateKey(rsaKeyJWEEncryption.toPrivateKey());

      when(session.keys()).thenReturn(mock(KeyManager.class));
      when(session.keys().getKey(any(),eq("RSA-OEAP-KID"),eq(KeyUse.ENC),eq("RSA-OAEP-256"))).thenReturn(keyWrapperJWEEncryption);

      // Launch Crypto engine
      // Required for ECDSA Provider
      CryptoIntegration.init(KeycloakFixture.class.getClassLoader());

      // Context and Realm object are called during signature verify
      when(session.getContext()).thenReturn(mock(KeycloakContext.class));
      when(session.getContext().getRealm()).thenReturn(mock(RealmModel.class));
    }

    @Test
    void should_validate_rs256_signed_token_for_eidas1_level() throws ParseException, JOSEException {
      var config = givenConfigForIntegrationAndEidasLevel1();
      var provider = new FranceConnectIdentityProvider(session, config);

      var encodedToken = givenAnRSASignedEidas1JWT(rsaKeySign);
      var token = provider.validateToken(encodedToken);

      assertThat(token).isNotNull();
      assertThat(token.getSubject()).isEqualTo("fakeSub");
      assertThat(token.getIssuer()).isNotNull();
      assertThat(token.getOtherClaims())
          .containsEntry("acr", "eidas1");
    }

    @Test
    void should_validate_rsa_oaep_encrypted_token_for_eidas2_and_eidas3_levels() throws IOException, ParseException, JOSEException {
      var config = givenConfigForIntegrationPlusAndEidasLevel2();
      var provider = new FranceConnectIdentityProvider(session, config);

      var encodedToken = givenAnRSAOAEPJWEForAnECDSASignedEidas2JWTWithRegisteredKidInJWKS(ecKeySign, rsaKeyJWEEncryption);
      var token = provider.validateToken(encodedToken);

      assertThat(token).isNotNull();
      assertThat(token.getSubject()).isEqualTo("fakeSub");
      assertThat(token.getIssuer()).isNotEmpty();
      assertThat(token.getOtherClaims())
          .containsEntry("acr", "eidas2");
    }

    @Test
    void should_throw_exception_when_no_public_rsa_key_found_in_key_manager_to_decrypt_jwe_token() throws JOSEException {
      var config = givenConfigForIntegrationPlusAndEidasLevel2();
      var provider = new FranceConnectIdentityProvider(session, config);

      var jwe = givenAnRSAOAEPJWEForAnECDSASignedEidas2JWTWithRegisteredKidInJWKS(
          ecKeySign, generateRSA256Key("unknownKidInKeyManager")
      );

      assertThatThrownBy(() -> provider.validateToken(jwe))
          .isInstanceOf(IdentityBrokerException.class)
          .hasMessage("Private key not found in the realm to decrypt token algorithm RSA-OAEP-256");
    }

    @Test
    void should_throw_exception_when_no_public_key_found_in_json_web_key_set_for_asymmetric_signed_jwt() {
      var config = givenConfigForIntegrationPlusAndEidasLevel2();
      var provider = new FranceConnectIdentityProvider(session, config);

      var jwe = givenAnRSAOAEPJWE(
          rsaKeyJWEEncryption,
          givenAnES256SignedJWTWithUnknownKidInJWKS()
      );

      assertThatThrownBy(() -> provider.validateToken(jwe))
          .isInstanceOf(IdentityBrokerException.class)
          .hasMessage("token signature validation failed");
    }
  }

  @Nested
  class IdTokenInformationExtraction {

    // Used to create JWE (public key) and to decrypt JWE (private key)
    private RSAKey rsaKeyJWEEncryption;

    // Used to sign JWT
    private ECKey ecKeySign;

    // Used to sign UserInfo
    private ECKey ecKeySignUserInfo;

    private HttpClientProvider httpClientProvider;
    private CloseableHttpClient httpClient;

    @BeforeEach
    void setup() throws JOSEException, IOException {

      httpClient = mock(CloseableHttpClient.class);
      httpClientProvider = mock(HttpClientProvider.class);
      when(session.getProvider(HttpClientProvider.class)).thenReturn(httpClientProvider);
      when(httpClientProvider.getHttpClient()).thenReturn(httpClient);
      when(httpClientProvider.getMaxConsumedResponseSize()).thenReturn(840L);

      var asymmetricSignatureProvider = new AsymmetricSignatureProvider(session,"RS256");
      when(session.getProvider(SignatureProvider.class,"RS256")).thenReturn(asymmetricSignatureProvider);

      var eCDSASignatureProvider = new ECDSASignatureProvider(session,"ES256");
      when(session.getProvider(SignatureProvider.class,"ES256")).thenReturn(eCDSASignatureProvider);

      // Prepare RSA and EC signature

      ecKeySign = generateES256Key("ECDSA-KID");
      var keyWrapperECSignature = new KeyWrapper();
      keyWrapperECSignature.setKid(ecKeySign.getKeyID());
      keyWrapperECSignature.setPublicKey(ecKeySign.toPublicKey());
      keyWrapperECSignature.setType(KeyType.EC);;

      ecKeySignUserInfo = generateES256Key("USERINFO-ECDSA-KID");
      var keyWrapperECSignatureUserInfo = new KeyWrapper();
      keyWrapperECSignatureUserInfo.setKid(ecKeySignUserInfo.getKeyID());
      keyWrapperECSignatureUserInfo.setPublicKey(ecKeySignUserInfo.toPublicKey());
      keyWrapperECSignatureUserInfo.setType(KeyType.EC);;

      var publicKeyStorageProvider = mock((PublicKeyStorageProvider.class));
      when(session.getProvider(PublicKeyStorageProvider.class)).thenReturn(publicKeyStorageProvider);
      when(publicKeyStorageProvider.getPublicKey(any(),eq("ECDSA-KID"),eq("ES256"),any())).thenReturn(keyWrapperECSignature);
      when(publicKeyStorageProvider.getPublicKey(any(),eq("USERINFO-ECDSA-KID"),eq("ES256"),any())).thenReturn(keyWrapperECSignatureUserInfo);


      rsaKeyJWEEncryption = generateRSA256Key("RSA-OEAP-KID");

      var keyWrapperJWEEncryption = new KeyWrapper();
      keyWrapperJWEEncryption.setKid(rsaKeyJWEEncryption.getKeyID());
      keyWrapperJWEEncryption.setPublicKey(rsaKeyJWEEncryption.toPublicKey());
      keyWrapperJWEEncryption.setPrivateKey(rsaKeyJWEEncryption.toPrivateKey());

      when(session.keys()).thenReturn(mock(KeyManager.class));
      when(session.keys().getKey(any(),eq("RSA-OEAP-KID"),eq(KeyUse.ENC),eq("RSA-OAEP-256"))).thenReturn(keyWrapperJWEEncryption);

      // Launch Crypto engine
      // Required for ECDSA Provider
      CryptoIntegration.init(KeycloakFixture.class.getClassLoader());

      // Context and Realm object are called during signature verify
      when(session.getContext()).thenReturn(mock(KeycloakContext.class));
      when(session.getContext().getRealm()).thenReturn(mock(RealmModel.class));

    }

    @Test
    void should_extract_information_from_JWE_userinfo_endpoint_response_for_eidas2_and_eidas3_levels() throws IOException {

      var config = givenConfigForIntegrationPlusAndEidasLevel2();
      var provider = new FranceConnectIdentityProvider(session, config);

      var httpResponse = ClosableHttpResponse.from(
          Map.of(HttpHeaders.CONTENT_TYPE, "application/jwt"),
             givenAnRSAOAEPJWE(
                 rsaKeyJWEEncryption,
                 givenAnECDSASignedJWTWithRegisteredKidInJWKS(ecKeySignUserInfo, USERINFO_JWT)
             )
         );
      when(httpClient.execute(any()))
          .thenAnswer(answer -> httpResponse);

      var opaqueAccessToken = "2b3ea2e8-2d11-49a4-a369-5fb98d9d5315";
      var jweIdToken = givenAnRSAOAEPJWEForAnECDSASignedEidas2JWTWithRegisteredKidInJWKS(ecKeySign, rsaKeyJWEEncryption);

      var tokenEndpointResponse = generateTokenEndpointResponse(opaqueAccessToken, jweIdToken);

      var brokeredIdentityContext = provider.getFederatedIdentity(tokenEndpointResponse);

      assertThat(brokeredIdentityContext).isNotNull();
      assertThat(brokeredIdentityContext.getEmail()).isEqualTo("john.doe@gmail.com");
      assertThat(brokeredIdentityContext.getFirstName()).isEqualTo("John");
      assertThat(brokeredIdentityContext.getLastName()).isEqualTo("Doe");
      assertThat(brokeredIdentityContext.getUsername()).isEqualTo("john.doe@gmail.com");
      assertThat(brokeredIdentityContext.getId()).isEqualTo("fakeSub");
    }

    @Test
    void id_token_acr_claim_should_match_with_selected_eidas_level_from_admin_interface() throws IOException {

      var config = givenConfigForIntegrationPlusAndEidasLevel2();
      var provider = new FranceConnectIdentityProvider(session, config);

      var httpResponse = ClosableHttpResponse.from(
          Map.of(HttpHeaders.CONTENT_TYPE, "application/jwt"),
          givenAnRSAOAEPJWE(
              rsaKeyJWEEncryption,
              givenAnECDSASignedJWTWithRegisteredKidInJWKS(ecKeySignUserInfo, USERINFO_JWT)
          )
      );
      when(httpClient.execute(any()))
          .thenAnswer(answer -> httpResponse);

      var opaqueAccessToken = "2b3ea2e8-2d11-49a4-a369-5fb98d9d5315";
      var jweIdToken = givenAnRSAOAEPJWEForAnECDSASignedEidas2JWTWithRegisteredKidInJWKS(ecKeySign, rsaKeyJWEEncryption);

      var tokenEndpointResponse = generateTokenEndpointResponse(opaqueAccessToken, jweIdToken);

      var brokeredIdentityContext = provider.getFederatedIdentity(tokenEndpointResponse);

      assertThat(brokeredIdentityContext).isNotNull();

      var idToken = (JsonWebToken) brokeredIdentityContext.getContextData().get(VALIDATED_ID_TOKEN);
      var acrClaim = (String) idToken.getOtherClaims().get("acr");

      assertThat(acrClaim).isEqualTo(config.getEidasLevel().toString());
    }

    @Test
    void should_extract_information_from_JWT_userinfo_endpoint_response_for_eidas1() throws IOException {

      var config = givenConfigForIntegrationAndEidasLevel1();
      var provider = new FranceConnectIdentityProvider(session, config);

      var httpResponse = ClosableHttpResponse.from(
          Map.of(HttpHeaders.CONTENT_TYPE, "application/jwt"),
          SignatureUtils.givenAnECDSASignedJWTWithRegisteredKidInJWKS(ecKeySignUserInfo, USERINFO_JWT)
      );
      when(httpClient.execute(any()))
          .thenAnswer(answer -> httpResponse);

      var opaqueAccessToken = "2b3ea2e8-2d11-49a4-a369-5fb98d9d5315";
      var jweIdToken = SignatureUtils.givenAnECDSASignedJWTWithRegisteredKidInJWKS(ecKeySign, EIDAS1_JWT);

      var tokenEndpointResponse = generateTokenEndpointResponse(opaqueAccessToken, jweIdToken);

      var brokeredIdentityContext = provider.getFederatedIdentity(tokenEndpointResponse);

      assertThat(brokeredIdentityContext).isNotNull();
      assertThat(brokeredIdentityContext.getEmail()).isEqualTo("john.doe@gmail.com");
      assertThat(brokeredIdentityContext.getFirstName()).isEqualTo("John");
      assertThat(brokeredIdentityContext.getLastName()).isEqualTo("Doe");
      assertThat(brokeredIdentityContext.getUsername()).isEqualTo("john.doe@gmail.com");
      assertThat(brokeredIdentityContext.getId()).isEqualTo("fakeSub");
    }

    @Test
    void should_extract_information_from_userinfo_endpoint_response_for_json_media_type() throws IOException {

      var config = givenConfigForIntegrationPlusAndEidasLevel2();
      var provider = new FranceConnectIdentityProvider(session, config);

      var httpResponse = ClosableHttpResponse.from(
          Map.of(HttpHeaders.CONTENT_TYPE, "application/json"),
          USERINFO_JWT.toString()
      );
      when(httpClient.execute(any()))
          .thenAnswer(answer -> httpResponse);

      var opaqueAccessToken = "2b3ea2e8-2d11-49a4-a369-5fb98d9d5315";
      var jweIdToken = givenAnRSAOAEPJWEForAnECDSASignedEidas2JWTWithRegisteredKidInJWKS(ecKeySign, rsaKeyJWEEncryption);

      var tokenEndpointResponse = generateTokenEndpointResponse(opaqueAccessToken, jweIdToken);

      var brokeredIdentityContext = provider.getFederatedIdentity(tokenEndpointResponse);

      assertThat(brokeredIdentityContext).isNotNull();
      assertThat(brokeredIdentityContext.getEmail()).isEqualTo("john.doe@gmail.com");
      assertThat(brokeredIdentityContext.getFirstName()).isEqualTo("John");
      assertThat(brokeredIdentityContext.getLastName()).isEqualTo("Doe");
      assertThat(brokeredIdentityContext.getUsername()).isEqualTo("john.doe@gmail.com");
      assertThat(brokeredIdentityContext.getId()).isEqualTo("fakeSub");
    }

    @Test
    void should_throw_exception_when_id_token_acr_claim_does_not_match_with_the_selected_eidas_level_from_admin_interface() throws IOException {

      var config = givenConfigForIntegrationPlusAndEidasLevel2();
      config.getConfig().put(EidasLevel.EIDAS_LEVEL_PROPERTY_NAME, EidasLevel.EIDAS3.toString());
      var provider = new FranceConnectIdentityProvider(session, config);

      var httpResponse = ClosableHttpResponse.from(
          Map.of(HttpHeaders.CONTENT_TYPE, "application/jwt"),
          givenAnRSAOAEPJWE(
              rsaKeyJWEEncryption,
              givenAnECDSASignedJWTWithRegisteredKidInJWKS(ecKeySignUserInfo, USERINFO_JWT)
          )
      );
      when(httpClient.execute(any()))
          .thenAnswer(answer -> httpResponse);

      var opaqueAccessToken = "2b3ea2e8-2d11-49a4-a369-5fb98d9d5315";
      var jweIdTokenWithEidas1 = givenAnRSAOAEPJWE(
          rsaKeyJWEEncryption,
          givenAnECDSASignedJWTWithRegisteredKidInJWKS(ecKeySign, EIDAS2_JWT)
      );

      var tokenEndpointResponse = generateTokenEndpointResponse(opaqueAccessToken, jweIdTokenWithEidas1);

      assertThatThrownBy(() -> provider.getFederatedIdentity(tokenEndpointResponse))
          .isInstanceOf(IdentityBrokerException.class)
          .hasMessage("The returned eIDAS level is insufficient");
    }

    @Test
    void should_throw_exception_when_id_token_does_not_contains_acr_claim() throws IOException {

      var config = givenConfigForIntegrationPlusAndEidasLevel2();
      var provider = new FranceConnectIdentityProvider(session, config);

      var httpResponse = ClosableHttpResponse.from(
          Map.of(HttpHeaders.CONTENT_TYPE, "application/jwt"),
          givenAnRSAOAEPJWE(
              rsaKeyJWEEncryption,
              givenAnECDSASignedJWTWithRegisteredKidInJWKS(ecKeySignUserInfo, USERINFO_JWT)
          )
      );
      when(httpClient.execute(any()))
          .thenAnswer(answer -> httpResponse);

      var opaqueAccessToken = "2b3ea2e8-2d11-49a4-a369-5fb98d9d5315";
      var jweIdTokenWithoutEidasLevel = givenAnRSAOAEPJWE(
          rsaKeyJWEEncryption,
          givenAnECDSASignedJWTWithRegisteredKidInJWKS(ecKeySign, NO_EIDAS_LEVEL_JWT)
      );

      var tokenEndpointResponse = generateTokenEndpointResponse(opaqueAccessToken, jweIdTokenWithoutEidasLevel);

      assertThatThrownBy(() -> provider.getFederatedIdentity(tokenEndpointResponse))
          .isInstanceOf(IdentityBrokerException.class)
          .hasMessage("The returned eIDAS level cannot be retrieved");
    }

    @Test
    void should_throw_exception_when_id_token_contains_acr_claim_who_does_not_match_with_a_supported_eidas_level() throws IOException {

      var config = givenConfigForIntegrationPlusAndEidasLevel2();
      var provider = new FranceConnectIdentityProvider(session, config);

      var httpResponse = ClosableHttpResponse.from(
          Map.of(HttpHeaders.CONTENT_TYPE, "application/jwt"),
          givenAnRSAOAEPJWE(
              rsaKeyJWEEncryption,
              givenAnECDSASignedJWTWithRegisteredKidInJWKS(ecKeySignUserInfo, USERINFO_JWT)
          )
      );
      when(httpClient.execute(any()))
          .thenAnswer(answer -> httpResponse);

      var opaqueAccessToken = "2b3ea2e8-2d11-49a4-a369-5fb98d9d5315";
      var jweIdTokenWithoutEidasLevel = givenAnRSAOAEPJWE(
          rsaKeyJWEEncryption,
          givenAnECDSASignedJWTWithRegisteredKidInJWKS(ecKeySign, UNSUPPORTED_EIDAS_LEVEL_JWT)
      );

      var tokenEndpointResponse = generateTokenEndpointResponse(opaqueAccessToken, jweIdTokenWithoutEidasLevel);

      assertThatThrownBy(() -> provider.getFederatedIdentity(tokenEndpointResponse))
          .isInstanceOf(IdentityBrokerException.class)
          .hasMessage("The returned eIDAS level cannot be retrieved");
    }
  }

  @Nested
  class IdTokenForLogout {

    private FranceConnectIdentityProvider logoutProvider;
    private UserSessionModel userSession;

    @BeforeEach
    void setup() {
      var logoutConfig = givenConfigForIntegrationAndEidasLevel1();
      logoutConfig.setAlias("franceconnect");
      logoutProvider = new FranceConnectIdentityProvider(session, logoutConfig);
      userSession = mock(UserSessionModel.class);
    }

    @Test
    void should_read_the_id_token_note_suffixed_with_the_provider_alias() {
      when(userSession.getNote("FEDERATED_ID_TOKEN:franceconnect")).thenReturn("suffixedIdToken");
      when(userSession.getNote("FEDERATED_ID_TOKEN")).thenReturn("legacyIdToken");

      assertThat(logoutProvider.getIdTokenForLogout(userSession)).isEqualTo("suffixedIdToken");
    }

    @Test
    void should_fall_back_to_the_id_token_note_without_alias() {
      when(userSession.getNote("FEDERATED_ID_TOKEN")).thenReturn("legacyIdToken");

      assertThat(logoutProvider.getIdTokenForLogout(userSession)).isEqualTo("legacyIdToken");
    }
  }
}
