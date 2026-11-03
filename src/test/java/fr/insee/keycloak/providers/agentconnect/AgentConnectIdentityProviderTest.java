package fr.insee.keycloak.providers.agentconnect;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import fr.insee.keycloak.providers.common.EidasLevel;
import fr.insee.keycloak.utils.ClosableHttpResponse;
import fr.insee.keycloak.utils.KeycloakFixture;
import fr.insee.keycloak.utils.TestUtils;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
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
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import static fr.insee.keycloak.providers.agentconnect.ACFixture.*;
import static fr.insee.keycloak.utils.KeycloakFixture.givenAuthenticationRequest;
import static fr.insee.keycloak.utils.SignatureUtils.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

@DisplayNameGeneration(ReplaceUnderscores.class)
class AgentConnectIdentityProviderTest {

  private KeycloakSession session;

  @BeforeEach
  void setup() throws IOException {
      session = mock(KeycloakSession.class);
  }

  @Nested
  class AuthorizationUrlCreation {

    @Test
    void should_create_authorization_url_with_eidas_level_as_acr_values_query_param() {
      var config = givenConfigForIntegrationAndEidasLevel2();
      var provider = new AgentConnectIdentityProvider(session, config);

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
  }

  @Nested
  class IdTokenValidation {

    private RSAKey rsaKeySign;
    private ECKey ecKeySign;

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

      // Launch Crypto engine
      CryptoIntegration.init(KeycloakFixture.class.getClassLoader());

      // Context and Realm object are called during signature verify
      when(session.getContext()).thenReturn(mock(KeycloakContext.class));
      when(session.getContext().getRealm()).thenReturn(mock(RealmModel.class));
    }

    @Test
    void should_throw_exception_when_no_public_key_found_in_json_web_key_set_for_asymmetric_signed_jwt() {
      var config = givenConfigForIntegrationAndEidasLevel2();
      var provider = new AgentConnectIdentityProvider(session, config);

      assertThatThrownBy(() -> provider.validateToken(givenAnRSASignedJWTWithUnknownKidInJWKS()))
          .isInstanceOf(IdentityBrokerException.class)
          .hasMessage("token signature validation failed");
    }

    @Test
    void should_validate_rs256_signed_token() throws IOException {
      var config = givenConfigForIntegrationAndEidasLevel2();
      var provider = new AgentConnectIdentityProvider(session, config);

      var encodedToken = givenAnRSASignedEidas2JWTWithRegisteredKidInJWKS(rsaKeySign);

      var token = provider.validateToken(encodedToken);

      assertThat(token).isNotNull();
      assertThat(token.getSubject()).isEqualTo("fakeSub");
      assertThat(token.getIssuer()).isNotEmpty();
      assertThat(token.getOtherClaims())
          .containsEntry("acr", "eidas2");
    }

    @Test
    void should_validate_es256_signed_token() throws IOException {
      var config = givenConfigForIntegrationAndEidasLevel2();
      var provider = new AgentConnectIdentityProvider(session, config);

      var encodedToken = givenAnECDSASignedEidas2JWTWithRegisteredKidInJWKS(ecKeySign);

      var token = provider.validateToken(encodedToken);

      assertThat(token).isNotNull();
      assertThat(token.getSubject()).isEqualTo("fakeSub");
      assertThat(token.getIssuer()).isNotEmpty();
      assertThat(token.getOtherClaims())
          .containsEntry("acr", "eidas2");
    }
  }

  @Nested
  class IdTokenInformationExtraction {

    private HttpClientProvider httpClientProvider;
    private CloseableHttpClient httpClient;
    private RSAKey rsaKeySign;

    @BeforeEach
    void setup() throws IOException, JOSEException {

      httpClientProvider = mock(HttpClientProvider.class);
      httpClient = mock(CloseableHttpClient.class);
      when(session.getProvider(HttpClientProvider.class)).thenReturn(httpClientProvider);
      when(httpClientProvider.getHttpClient()).thenReturn(httpClient);
      when(httpClientProvider.getMaxConsumedResponseSize()).thenReturn(840L);

      var httpResponse = ClosableHttpResponse.from(
          Map.of(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON),
          USERINFO_JWT.toString()
      );

      when(httpClient.execute(any()))
          .thenAnswer(answer -> httpResponse);

      var asymmetricSignatureProvider = new AsymmetricSignatureProvider(session,"RS256");
      when(session.getProvider(SignatureProvider.class,"RS256")).thenReturn(asymmetricSignatureProvider);

      rsaKeySign = generateRSA256Key("RSA_KID");
      var keyWrapperRSASignature = new KeyWrapper();
      keyWrapperRSASignature.setKid(rsaKeySign.getKeyID());
      keyWrapperRSASignature.setPublicKey(rsaKeySign.toPublicKey());
      keyWrapperRSASignature.setType(KeyType.RSA);

      var publicKeyStorageProvider = mock((PublicKeyStorageProvider.class));
      when(session.getProvider(PublicKeyStorageProvider.class)).thenReturn(publicKeyStorageProvider);
      when(publicKeyStorageProvider.getPublicKey(any(),eq("RSA_KID"),eq("RS256"),any())).thenReturn(keyWrapperRSASignature);

      // Context and Realm object are called during signature verify
      when(session.getContext()).thenReturn(mock(KeycloakContext.class));
      when(session.getContext().getRealm()).thenReturn(mock(RealmModel.class));

    }

    @Test
    void id_token_acr_claim_should_match_with_selected_eidas_level_from_admin_interface() throws IOException {
      var config = givenConfigForIntegrationAndEidasLevel2();
      var provider = new AgentConnectIdentityProvider(session, config);

      var opaqueAccessToken = "2b3ea2e8-2d11-49a4-a369-5fb98d9d5315";
      var signedIdToken = givenAnRSASignedEidas2JWTWithRegisteredKidInJWKS(rsaKeySign);

      var tokenEndpointResponse = generateTokenEndpointResponse(opaqueAccessToken, signedIdToken);

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
      var config = givenConfigForIntegrationAndEidasLevel2();
      var provider = new AgentConnectIdentityProvider(session, config);

      var opaqueAccessToken = "2b3ea2e8-2d11-49a4-a369-5fb98d9d5315";
      var signedIdTokenWithEidas1 = givenAnRSASignedJWTWithRegisteredKidInJWKS(rsaKeySign, EIDAS1_JWT);

      var tokenEndpointResponse = generateTokenEndpointResponse(opaqueAccessToken, signedIdTokenWithEidas1);

      assertThatThrownBy(() -> provider.getFederatedIdentity(tokenEndpointResponse))
          .isInstanceOf(IdentityBrokerException.class)
          .hasMessage("The returned eIDAS level is insufficient");
    }

    @Test
    void should_throw_exception_when_id_token_does_not_contains_acr_claim() throws IOException {
      var config = givenConfigForIntegrationAndEidasLevel2();
      var provider = new AgentConnectIdentityProvider(session, config);

      var opaqueAccessToken = "2b3ea2e8-2d11-49a4-a369-5fb98d9d5315";
      var signedIdTokenWithoutEidasLevel = givenAnRSASignedJWTWithRegisteredKidInJWKS(rsaKeySign, NO_EIDAS_LEVEL_JWT);

      var tokenEndpointResponse = generateTokenEndpointResponse(opaqueAccessToken, signedIdTokenWithoutEidasLevel);

      assertThatThrownBy(() -> provider.getFederatedIdentity(tokenEndpointResponse))
          .isInstanceOf(IdentityBrokerException.class)
          .hasMessage("The returned eIDAS level cannot be retrieved");
    }

    @Test
    void should_throw_exception_when_id_token_contains_acr_claim_who_does_not_match_with_a_supported_eidas_level() throws IOException {
      var config = givenConfigForIntegrationAndEidasLevel2();
      var provider = new AgentConnectIdentityProvider(session, config);

      var opaqueAccessToken = "2b3ea2e8-2d11-49a4-a369-5fb98d9d5315";
      var signedIdTokenWithoutEidasLevel = givenAnRSASignedJWTWithRegisteredKidInJWKS(rsaKeySign, UNSUPPORTED_EIDAS_LEVEL_JWT);

      var tokenEndpointResponse = generateTokenEndpointResponse(opaqueAccessToken, signedIdTokenWithoutEidasLevel);

      assertThatThrownBy(() -> provider.getFederatedIdentity(tokenEndpointResponse))
          .isInstanceOf(IdentityBrokerException.class)
          .hasMessage("The returned eIDAS level cannot be retrieved");
    }
  }

  @Nested
  class MfaMode {

    private AgentConnectIdentityProviderConfig mfaConfig;
    private AgentConnectIdentityProvider mfaProvider;

    @BeforeEach
    void setupMfa() throws IOException {
      mfaConfig = givenConfigWithMfaEnabled();
      mfaConfig.setEnabled(true);

      mfaProvider = new AgentConnectIdentityProvider(session, mfaConfig);
    }

    @Nested
    class AuthorizationUrlCreation {

      @Test
      void should_create_authorization_url_with_claims_param_instead_of_acr_values_when_mfa_enabled() {
        var request = givenAuthenticationRequest(session);

        var authorizationUrl = mfaProvider.createAuthorizationUrl(request).build();
        var rawQuery = authorizationUrl.getRawQuery();

        assertThat(rawQuery).contains("claims=");
        assertThat(rawQuery).doesNotContain("acr_values=");
      }

      @Test
      void should_include_all_mfa_acr_values_in_claims_param_when_mfa_enabled_with_eidas1() throws URISyntaxException {
        var request = givenAuthenticationRequest(session);

        var authorizationUrl = mfaProvider.createAuthorizationUrl(request).build();
        var decodedQuery = URLDecoder.decode(authorizationUrl.getRawQuery(), StandardCharsets.UTF_8);

        assertThat(decodedQuery).contains("eidas0-mfa");
        assertThat(decodedQuery).contains("eidas1-mfa");
        assertThat(decodedQuery).contains("eidas2");
        assertThat(decodedQuery).contains("eidas3");
      }

      @Test
      void should_mark_acr_claim_as_essential_when_mfa_requirement_is_required() throws URISyntaxException {
        var request = givenAuthenticationRequest(session);

        var decodedQuery = URLDecoder.decode(
            mfaProvider.createAuthorizationUrl(request).build().getRawQuery(),
            StandardCharsets.UTF_8
        );

        assertThat(decodedQuery).contains("\"essential\":true");
      }

      @Test
      void should_mark_acr_claim_as_non_essential_when_mfa_requirement_is_optional() throws URISyntaxException {
        mfaConfig = givenConfigWithMfaRequirementAndEidasLevel(MfaRequirement.OPTIONAL, EidasLevel.EIDAS1.toString());
        mfaConfig.setEnabled(true);
        mfaProvider = new AgentConnectIdentityProvider(session, mfaConfig);
        var request = givenAuthenticationRequest(session);

        var decodedQuery = URLDecoder.decode(
            mfaProvider.createAuthorizationUrl(request).build().getRawQuery(),
            StandardCharsets.UTF_8
        );

        assertThat(decodedQuery).contains("claims=");
        assertThat(decodedQuery).contains("\"essential\":false");
      }

      @Test
      void should_include_only_eidas2_and_eidas3_in_claims_param_when_mfa_enabled_with_eidas2() throws URISyntaxException {
        mfaConfig = givenConfigWithMfaEnabledAndEidasLevel(EidasLevel.EIDAS2.toString());
        mfaConfig.setEnabled(true);
        mfaProvider = new AgentConnectIdentityProvider(session, mfaConfig);
        var request = givenAuthenticationRequest(session);

        var decodedQuery = URLDecoder.decode(
            mfaProvider.createAuthorizationUrl(request).build().getRawQuery(),
            StandardCharsets.UTF_8
        );

        assertThat(decodedQuery).contains("eidas2");
        assertThat(decodedQuery).contains("eidas3");
        assertThat(decodedQuery).doesNotContain("eidas0-mfa");
        assertThat(decodedQuery).doesNotContain("eidas1-mfa");
      }

      @Test
      void should_include_only_eidas3_in_claims_param_when_mfa_enabled_with_eidas3() throws URISyntaxException {
        mfaConfig = givenConfigWithMfaEnabledAndEidasLevel(EidasLevel.EIDAS3.toString());
        mfaConfig.setEnabled(true);
        mfaProvider = new AgentConnectIdentityProvider(session, mfaConfig);
        var request = givenAuthenticationRequest(session);

        var decodedQuery = URLDecoder.decode(
            mfaProvider.createAuthorizationUrl(request).build().getRawQuery(),
            StandardCharsets.UTF_8
        );

        assertThat(decodedQuery).contains("eidas3");
        assertThat(decodedQuery).doesNotContain("eidas0-mfa");
        assertThat(decodedQuery).doesNotContain("eidas1-mfa");
        assertThat(decodedQuery).doesNotContain("eidas2");
      }
    }

    @Nested
    class AcrValidation {

      private HttpClientProvider httpClientProvider;
      private CloseableHttpClient httpClient;
      private RSAKey rsaKeySign;

      @BeforeEach
      void setupHttpResponse() throws IOException, JOSEException {

        httpClientProvider = mock(HttpClientProvider.class);
        httpClient = mock(CloseableHttpClient.class);
        when(session.getProvider(HttpClientProvider.class)).thenReturn(httpClientProvider);
        when(httpClientProvider.getHttpClient()).thenReturn(httpClient);
        when(httpClientProvider.getMaxConsumedResponseSize()).thenReturn(840L);

        var httpResponse = ClosableHttpResponse.from(
            Map.of(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON),
            USERINFO_JWT.toString()
        );
        when(httpClient.execute(any())).thenAnswer(answer -> httpResponse);

        var asymmetricSignatureProvider = new AsymmetricSignatureProvider(session,"RS256");
        when(session.getProvider(SignatureProvider.class,"RS256")).thenReturn(asymmetricSignatureProvider);

        rsaKeySign = generateRSA256Key("RSA_KID");
        var keyWrapperRSASignature = new KeyWrapper();
        keyWrapperRSASignature.setKid(rsaKeySign.getKeyID());
        keyWrapperRSASignature.setPublicKey(rsaKeySign.toPublicKey());
        keyWrapperRSASignature.setType(KeyType.RSA);

        var publicKeyStorageProvider = mock((PublicKeyStorageProvider.class));
        when(session.getProvider(PublicKeyStorageProvider.class)).thenReturn(publicKeyStorageProvider);
        when(publicKeyStorageProvider.getPublicKey(any(),eq("RSA_KID"),eq("RS256"),any())).thenReturn(keyWrapperRSASignature);

        // Context and Realm object are called during signature verify
        when(session.getContext()).thenReturn(mock(KeycloakContext.class));
        when(session.getContext().getRealm()).thenReturn(mock(RealmModel.class));

      }

      @Test
      void should_accept_eidas0_mfa_acr_value_when_mfa_enabled_with_eidas1() throws IOException {
        assertMfaAcrIsAccepted(EIDAS0_MFA_JWT);
      }

      @Test
      void should_accept_eidas1_mfa_acr_value_when_mfa_enabled_with_eidas1() throws IOException {
        assertMfaAcrIsAccepted(EIDAS1_MFA_JWT);
      }

      @Test
      void should_accept_eidas2_acr_value_when_mfa_enabled() throws IOException {
        assertMfaAcrIsAccepted(EIDAS2_JWT);
      }

      @Test
      void should_accept_eidas3_acr_value_when_mfa_enabled() throws IOException {
        assertMfaAcrIsAccepted(EIDAS3_JWT);
      }

      @Test
      void should_reject_eidas1_mfa_acr_value_when_mfa_enabled_with_eidas2() throws IOException {
        mfaConfig = givenConfigWithMfaEnabledAndEidasLevel(EidasLevel.EIDAS2.toString());
        mfaConfig.setEnabled(true);
        mfaProvider = new AgentConnectIdentityProvider(session, mfaConfig);

        assertMfaAcrIsRejected(EIDAS1_MFA_JWT);
      }

      private void assertMfaAcrIsAccepted(JWTClaimsSet jwtClaimsSet) throws IOException {

        var opaqueAccessToken = "2b3ea2e8-2d11-49a4-a369-5fb98d9d5315";
        var signedIdToken = givenAnRSASignedJWTWithRegisteredKidInJWKS(rsaKeySign, jwtClaimsSet);

        var tokenEndpointResponse = generateTokenEndpointResponse(opaqueAccessToken, signedIdToken);

        var brokeredIdentityContext = mfaProvider.getFederatedIdentity(tokenEndpointResponse);
        assertThat(brokeredIdentityContext).isNotNull();
      }

      private void assertMfaAcrIsRejected(JWTClaimsSet jwtClaimsSet) throws IOException {

        var opaqueAccessToken = "2b3ea2e8-2d11-49a4-a369-5fb98d9d5315";
        var signedIdToken = givenAnRSASignedJWTWithRegisteredKidInJWKS(rsaKeySign, jwtClaimsSet);

        var tokenEndpointResponse = generateTokenEndpointResponse(opaqueAccessToken, signedIdToken);

        assertThatThrownBy(() -> mfaProvider.getFederatedIdentity(tokenEndpointResponse))
            .isInstanceOf(IdentityBrokerException.class)
            .hasMessage(AgentConnectIdentityProvider.MFA_INSUFFICIENT_ACR_ERROR_MESSAGE);
      }

      @Test
      void should_throw_exception_when_acr_claim_is_not_a_2fa_value_and_mfa_is_required() throws IOException {
        assertMfaAcrIsRejected(EIDAS1_JWT);
      }

      @Test
      void should_accept_non_mfa_acr_value_when_mfa_requirement_is_optional() throws IOException {
        mfaConfig = givenConfigWithMfaRequirementAndEidasLevel(MfaRequirement.OPTIONAL, EidasLevel.EIDAS1.toString());
        mfaConfig.setEnabled(true);
        mfaProvider = new AgentConnectIdentityProvider(session, mfaConfig);

        assertMfaAcrIsAccepted(EIDAS1_JWT);
      }

      @Test
      void should_accept_mfa_acr_value_when_mfa_requirement_is_optional() throws IOException {
        mfaConfig = givenConfigWithMfaRequirementAndEidasLevel(MfaRequirement.OPTIONAL, EidasLevel.EIDAS1.toString());
        mfaConfig.setEnabled(true);
        mfaProvider = new AgentConnectIdentityProvider(session, mfaConfig);

        assertMfaAcrIsAccepted(EIDAS1_MFA_JWT);
      }

      @Test
      void should_reject_insufficient_eidas_level_when_mfa_requirement_is_optional() throws IOException {
        mfaConfig = givenConfigWithMfaRequirementAndEidasLevel(MfaRequirement.OPTIONAL, EidasLevel.EIDAS2.toString());
        mfaConfig.setEnabled(true);
        mfaProvider = new AgentConnectIdentityProvider(session, mfaConfig);

        var opaqueAccessToken = "2b3ea2e8-2d11-49a4-a369-5fb98d9d5315";
        var signedIdToken = givenAnRSASignedJWTWithRegisteredKidInJWKS(rsaKeySign, EIDAS1_JWT);

        var tokenEndpointResponse = generateTokenEndpointResponse(opaqueAccessToken, signedIdToken);

        assertThatThrownBy(() -> mfaProvider.getFederatedIdentity(tokenEndpointResponse))
            .isInstanceOf(IdentityBrokerException.class)
            .hasMessage("The returned eIDAS level is insufficient");
      }

      @Test
      void should_accept_mfa_acr_value_when_mfa_is_disabled() throws IOException {
        mfaConfig = givenConfigWithMfaRequirementAndEidasLevel(MfaRequirement.DISABLED, EidasLevel.EIDAS1.toString());
        mfaConfig.setEnabled(true);
        mfaProvider = new AgentConnectIdentityProvider(session, mfaConfig);

        assertMfaAcrIsAccepted(EIDAS1_MFA_JWT);
      }
    }
  }
}
