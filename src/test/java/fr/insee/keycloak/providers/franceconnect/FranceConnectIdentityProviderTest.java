package fr.insee.keycloak.providers.franceconnect;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.RSAKey;
import fr.insee.keycloak.providers.common.EidasLevel;
import fr.insee.keycloak.utils.*;
import org.apache.http.impl.client.CloseableHttpClient;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator.ReplaceUnderscores;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.models.KeyManager;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.representations.JsonWebToken;
import org.mockito.Mockito;

import jakarta.ws.rs.core.HttpHeaders;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Map;
import java.util.stream.Stream;

import static fr.insee.keycloak.providers.franceconnect.FCFixture.*;
import static fr.insee.keycloak.utils.KeycloakFixture.givenAuthenticationRequest;
import static fr.insee.keycloak.utils.KeycloakFixture.givenKeycloakSession;
import static fr.insee.keycloak.utils.SignatureUtils.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.keycloak.broker.oidc.OIDCIdentityProvider.VALIDATED_ID_TOKEN;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@DisplayNameGeneration(ReplaceUnderscores.class)
class FranceConnectIdentityProviderTest {

  // Used by KeycloakSession
  private HttpClientProvider httpClientProvider;
  private CloseableHttpClient httpClient;
  private KeycloakSession session;

  private FranceConnectIdentityProviderConfig config;
  private FranceConnectIdentityProvider provider;
  private PublicKeysStore publicKeysStore;

  @BeforeEach
  void setup() throws IOException {
    config = givenConfigForIntegrationV2AndEidasLevel2();
    publicKeysStore = new PublicKeysStore();

    httpClientProvider = mock(HttpClientProvider.class);
    httpClient = mock(CloseableHttpClient.class);

    when(httpClientProvider.get(config.getJwksUrl()))
        .thenAnswer(
            answer -> new ByteArrayInputStream(publicKeysStore.toJsonByteArray())
        );
    session = givenKeycloakSession(httpClientProvider, httpClient);

    provider = new FranceConnectIdentityProvider(session, config);
  }

  @Test
  void should_load_jwks_from_jwks_url_when_configuration_supports_jwks() throws IOException {
    verify(httpClientProvider, times(1)).get(config.getJwksUrl());

    var noJWKSSupportsConfig = givenConfigForIntegrationV1AndEidasLevel2();
    var httpClientProvider = mock(HttpClientProvider.class);
    var session = givenKeycloakSession(httpClientProvider, httpClient);

    var provider = new FranceConnectIdentityProvider(session, noJWKSSupportsConfig);

    verify(httpClientProvider, never()).get(anyString());
  }

  @Nested
  class AuthorizationUrlCreation {

    @Test
    void should_create_authorization_url_with_eidas_level_as_acr_values_query_param() {
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
    void should_create_authorization_url_with_nonce_query_param_having_exactly_64_chars() {
      var request = givenAuthenticationRequest(session);

      var authorizationUrl = provider.createAuthorizationUrl(request).build();
      var queryParams = TestUtils.uriQueryStringToMap(authorizationUrl);

      assertThat(authorizationUrl.toString()).startsWith(config.getAuthorizationUrl());
      assertThat(queryParams).hasEntrySatisfying("nonce", value -> assertThat(value).hasSize(64));
    }
  }

  @Nested
  class IdTokenValidation {

    // Used to create JWE (public key) and to decrypt JWE (private key)
    private RSAKey rsaKey;

    @BeforeEach
    void setup() throws JOSEException {
      rsaKey = generateRSA256Key("RSA-OEAP-KID");

      var keyWrapper = new KeyWrapper();
      keyWrapper.setKid(rsaKey.getKeyID());
      keyWrapper.setPublicKey(rsaKey.toPublicKey());
      keyWrapper.setPrivateKey(rsaKey.toPrivateKey());

      var keyManager = mock(KeyManager.class);
      when(session.keys()).thenReturn(keyManager);
      when(session.getContext()).thenReturn(mock(KeycloakContext.class));

      when(keyManager.getKeysStream(any()))
          .thenReturn(Stream.of(keyWrapper));
    }

    @Test
    void should_validate_hs256_signed_token_for_eidas1_level() {
      // Change current selected eidas level in config
      config.getConfig().put(EidasLevel.EIDAS_LEVEL_PROPERTY_NAME, "eidas1");

      var token = provider.validateToken(givenAnHMACSignedEidas1JWT());

      assertThat(token).isNotNull();
      assertThat(token.getSubject()).isEqualTo("fakeSub");
      assertThat(token.getIssuer()).isNotNull();
      assertThat(token.getOtherClaims())
          .containsEntry("acr", "eidas1");
    }

    @Test
    void should_search_in_vault_for_secret_key_on_hs256_token_validation() {
      // Change current selected eidas level in config
      config.getConfig().put(EidasLevel.EIDAS_LEVEL_PROPERTY_NAME, "eidas1");

      provider.validateToken(givenAnHMACSignedEidas1JWT());

      verify(session.vault(), Mockito.atLeastOnce()).getStringSecret(anyString());
    }

    @Test
    void should_validate_rsa_oaep_encrypted_token_for_eidas2_and_eidas3_levels() {
      var token = provider.validateToken(
          givenAnRSAOAEPJWEForAnECDSASignedEidas2JWTWithRegisteredKidInJWKS("ECDSA-KID", publicKeysStore, rsaKey)
      );

      assertThat(token).isNotNull();
      assertThat(token.getSubject()).isEqualTo("fakeSub");
      assertThat(token.getIssuer()).isNotEmpty();
      assertThat(token.getOtherClaims())
          .containsEntry("acr", "eidas2");
    }

    @Test
    void should_throw_exception_when_no_public_rsa_key_found_in_key_manager_to_decrypt_jwe_token() {
      var jwe = givenAnRSAOAEPJWEForAnECDSASignedEidas2JWTWithRegisteredKidInJWKS(
          "ECDSA-KID", publicKeysStore, generateRSA256Key("unknownKidInKeyManager")
      );

      assertThatThrownBy(() -> provider.validateToken(jwe))
          .isInstanceOf(IdentityBrokerException.class)
          .hasMessage("No key found for kid unknownKidInKeyManager");
    }

    @Test
    void should_throw_exception_when_no_public_key_found_in_json_web_key_set_for_asymmetric_signed_jwt() {
      var jwe = givenAnRSAOAEPJWE(
          rsaKey,
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
    private RSAKey rsaKey;

    @BeforeEach
    void setup() throws JOSEException, IOException {
      rsaKey = generateRSA256Key("RSA-OEAP-KID");

      var keyWrapper = new KeyWrapper();
      keyWrapper.setKid(rsaKey.getKeyID());
      keyWrapper.setPublicKey(rsaKey.toPublicKey());
      keyWrapper.setPrivateKey(rsaKey.toPrivateKey());

      var keyManager = mock(KeyManager.class);
      when(session.keys()).thenReturn(keyManager);
      when(session.getContext()).thenReturn(mock(KeycloakContext.class));

      when(keyManager.getKeysStream(any()))
          .thenAnswer(answer -> Stream.of(keyWrapper));

    }

    @Test
    void should_extract_information_from_JWE_userinfo_endpoint_response_for_eidas2_and_eidas3_levels() throws IOException {

      var httpResponse = ClosableHttpResponse.from(
          Map.of(HttpHeaders.CONTENT_TYPE, "application/jwt"),
             givenAnRSAOAEPJWE(
                rsaKey,
                 givenAnECDSASignedJWTWithRegisteredKidInJWKS("USERINFO-ECDSA-KID", USERINFO_JWT, publicKeysStore)
             )
         );
      when(httpClient.execute(any()))
          .thenAnswer(answer -> httpResponse);

      var kid = "ECDSA-KID";
      var opaqueAccessToken = "2b3ea2e8-2d11-49a4-a369-5fb98d9d5315";
      var jweIdToken = givenAnRSAOAEPJWEForAnECDSASignedEidas2JWTWithRegisteredKidInJWKS(kid, publicKeysStore, rsaKey);

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

      var httpResponse = ClosableHttpResponse.from(
          Map.of(HttpHeaders.CONTENT_TYPE, "application/jwt"),
          givenAnRSAOAEPJWE(
              rsaKey,
              givenAnECDSASignedJWTWithRegisteredKidInJWKS("USERINFO-ECDSA-KID", USERINFO_JWT, publicKeysStore)
          )
      );
      when(httpClient.execute(any()))
          .thenAnswer(answer -> httpResponse);

      var kid = "ECDSA-KID";
      var opaqueAccessToken = "2b3ea2e8-2d11-49a4-a369-5fb98d9d5315";
      var jweIdToken = givenAnRSAOAEPJWEForAnECDSASignedEidas2JWTWithRegisteredKidInJWKS(kid, publicKeysStore, rsaKey);

      var tokenEndpointResponse = generateTokenEndpointResponse(opaqueAccessToken, jweIdToken);

      var brokeredIdentityContext = provider.getFederatedIdentity(tokenEndpointResponse);

      assertThat(brokeredIdentityContext).isNotNull();

      var idToken = (JsonWebToken) brokeredIdentityContext.getContextData().get(VALIDATED_ID_TOKEN);
      var acrClaim = (String) idToken.getOtherClaims().get("acr");

      assertThat(acrClaim).isEqualTo(config.getEidasLevel().toString());
    }

    @Test
    void should_extract_information_from_JWT_userinfo_endpoint_response_for_eidas1() throws IOException {
      // Change current selected eidas level in config
      config.getConfig().put(EidasLevel.EIDAS_LEVEL_PROPERTY_NAME, "eidas1");

      var httpResponse = ClosableHttpResponse.from(
          Map.of(HttpHeaders.CONTENT_TYPE, "application/jwt"),
          SignatureUtils.givenAnECDSASignedJWTWithRegisteredKidInJWKS("USERINFO-ECDSA-KID", USERINFO_JWT, publicKeysStore)
      );
      when(httpClient.execute(any()))
          .thenAnswer(answer -> httpResponse);

      var kid = "ECDSA-KID";
      var opaqueAccessToken = "2b3ea2e8-2d11-49a4-a369-5fb98d9d5315";
      var jweIdToken = SignatureUtils.givenAnECDSASignedJWTWithRegisteredKidInJWKS(kid, EIDAS1_JWT, publicKeysStore);

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
      var httpResponse = ClosableHttpResponse.from(
          Map.of(HttpHeaders.CONTENT_TYPE, "application/json"),
          USERINFO_JWT.toString()
      );
      when(httpClient.execute(any()))
          .thenAnswer(answer -> httpResponse);

      var kid = "ECDSA-KID";
      var opaqueAccessToken = "2b3ea2e8-2d11-49a4-a369-5fb98d9d5315";
      var jweIdToken = givenAnRSAOAEPJWEForAnECDSASignedEidas2JWTWithRegisteredKidInJWKS(kid, publicKeysStore, rsaKey);

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

      var httpResponse = ClosableHttpResponse.from(
          Map.of(HttpHeaders.CONTENT_TYPE, "application/jwt"),
          givenAnRSAOAEPJWE(
              rsaKey,
              givenAnECDSASignedJWTWithRegisteredKidInJWKS("USERINFO-ECDSA-KID", USERINFO_JWT, publicKeysStore)
          )
      );
      when(httpClient.execute(any()))
          .thenAnswer(answer -> httpResponse);

      var kid = "ECDSA-KID";
      var opaqueAccessToken = "2b3ea2e8-2d11-49a4-a369-5fb98d9d5315";
      var jweIdTokenWithEidas1 = givenAnRSAOAEPJWE(
          rsaKey,
          givenAnECDSASignedJWTWithRegisteredKidInJWKS(kid, EIDAS1_JWT, publicKeysStore)
      );

      var tokenEndpointResponse = generateTokenEndpointResponse(opaqueAccessToken, jweIdTokenWithEidas1);

      assertThatThrownBy(() -> provider.getFederatedIdentity(tokenEndpointResponse))
          .isInstanceOf(IdentityBrokerException.class)
          .hasMessage("The returned eIDAS level is insufficient");
    }

    @Test
    void should_throw_exception_when_id_token_does_not_contains_acr_claim() throws IOException {

      var httpResponse = ClosableHttpResponse.from(
          Map.of(HttpHeaders.CONTENT_TYPE, "application/jwt"),
          givenAnRSAOAEPJWE(
              rsaKey,
              givenAnECDSASignedJWTWithRegisteredKidInJWKS("USERINFO-ECDSA-KID", USERINFO_JWT, publicKeysStore)
          )
      );
      when(httpClient.execute(any()))
          .thenAnswer(answer -> httpResponse);

      var kid = "ECDSA-KID";
      var opaqueAccessToken = "2b3ea2e8-2d11-49a4-a369-5fb98d9d5315";
      var jweIdTokenWithoutEidasLevel = givenAnRSAOAEPJWE(
          rsaKey,
          givenAnECDSASignedJWTWithRegisteredKidInJWKS(kid, NO_EIDAS_LEVEL_JWT, publicKeysStore)
      );

      var tokenEndpointResponse = generateTokenEndpointResponse(opaqueAccessToken, jweIdTokenWithoutEidasLevel);

      assertThatThrownBy(() -> provider.getFederatedIdentity(tokenEndpointResponse))
          .isInstanceOf(IdentityBrokerException.class)
          .hasMessage("The returned eIDAS level cannot be retrieved");
    }

    @Test
    void should_throw_exception_when_id_token_contains_acr_claim_who_does_not_match_with_a_supported_eidas_level() throws IOException {

      var httpResponse = ClosableHttpResponse.from(
          Map.of(HttpHeaders.CONTENT_TYPE, "application/jwt"),
          givenAnRSAOAEPJWE(
              rsaKey,
              givenAnECDSASignedJWTWithRegisteredKidInJWKS("USERINFO-ECDSA-KID", USERINFO_JWT, publicKeysStore)
          )
      );
      when(httpClient.execute(any()))
          .thenAnswer(answer -> httpResponse);

      var kid = "ECDSA-KID";
      var opaqueAccessToken = "2b3ea2e8-2d11-49a4-a369-5fb98d9d5315";
      var jweIdTokenWithoutEidasLevel = givenAnRSAOAEPJWE(
          rsaKey,
          givenAnECDSASignedJWTWithRegisteredKidInJWKS(kid, UNSUPPORTED_EIDAS_LEVEL_JWT, publicKeysStore)
      );

      var tokenEndpointResponse = generateTokenEndpointResponse(opaqueAccessToken, jweIdTokenWithoutEidasLevel);

      assertThatThrownBy(() -> provider.getFederatedIdentity(tokenEndpointResponse))
          .isInstanceOf(IdentityBrokerException.class)
          .hasMessage("The returned eIDAS level cannot be retrieved");
    }
  }
}
