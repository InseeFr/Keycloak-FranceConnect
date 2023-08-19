package fr.insee.keycloak.providers.agentconnect;

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
import org.keycloak.models.KeycloakSession;
import org.mockito.Mockito;

import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Map;

import static fr.insee.keycloak.providers.agentconnect.ACFixture.*;
import static fr.insee.keycloak.utils.KeycloakFixture.givenAuthenticationRequest;
import static fr.insee.keycloak.utils.KeycloakFixture.givenKeycloakSession;
import static fr.insee.keycloak.utils.SignatureUtils.generateTokenEndpointResponse;
import static fr.insee.keycloak.utils.SignatureUtils.givenAnRSASignedJWTWithRegisteredKidInJWKS;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@DisplayNameGeneration(ReplaceUnderscores.class)
class AgentConnectIdentityProviderTest {

  // Used by KeycloakSession
  private HttpClientProvider httpClientProvider;
  private CloseableHttpClient httpClient;
  private KeycloakSession session;

  private AgentConnectIdentityProviderConfig config;
  private AgentConnectIdentityProvider provider;
  private PublicKeysStore publicKeysStore;

  @BeforeEach
  void setup() throws IOException {
    config = givenConfigForIntegrationAndEidasLevel2();
    publicKeysStore = new PublicKeysStore();

    httpClientProvider = mock(HttpClientProvider.class);
    httpClient = mock(CloseableHttpClient.class);

    when(httpClientProvider.get(config.getJwksUrl()))
        .thenAnswer(answer -> new ByteArrayInputStream(publicKeysStore.toJsonByteArray()));
    session = givenKeycloakSession(httpClientProvider, httpClient);

    provider = new AgentConnectIdentityProvider(session, config);
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
  }

  @Nested
  class IdTokenValidation {

    @Test
    void should_validate_hs256_signed_token() {
      var token = provider.validateToken(givenAnHMACSignedEidas2JWT());

      assertThat(token).isNotNull();
      assertThat(token.getSubject()).isEqualTo("fakeSub");
      assertThat(token.getIssuer()).isNotEmpty();
      assertThat(token.getOtherClaims())
          .containsEntry("acr", "eidas2");
    }

    @Test
    void should_search_in_vault_for_secret_key_on_hs256_token_validation() {
      provider.validateToken(givenAnHMACSignedEidas2JWT());

      verify(session.vault(), Mockito.atLeastOnce()).getStringSecret(anyString());
    }

    @Test
    void should_throw_exception_when_no_public_key_found_in_json_web_key_set_for_asymmetric_signed_jwt() {
      assertThatThrownBy(() -> provider.validateToken(givenAnRSASignedJWTWithUnknownKidInJWKS()))
          .isInstanceOf(IdentityBrokerException.class)
          .hasMessage("token signature validation failed");
    }

    @Test
    void should_validate_rs256_signed_token() {
      var kid = "RSA-KID";
      // JWKS Reload should find the publicKey added by the givenAnRSA method
      var token = provider.validateToken(givenAnRSASignedEidas2JWTWithRegisteredKidInJWKS(kid, publicKeysStore));

      assertThat(token).isNotNull();
      assertThat(token.getSubject()).isEqualTo("fakeSub");
      assertThat(token.getIssuer()).isNotEmpty();
      assertThat(token.getOtherClaims())
          .containsEntry("acr", "eidas2");
    }

    @Test
    void should_validate_es256_signed_token() {
      var kid = "ECDSA-KID";
      // JWKS Reload should find the publicKey added by the givenAnECDSA method
      var token = provider.validateToken(givenAnECDSASignedEidas2JWTWithRegisteredKidInJWKS(kid, publicKeysStore));

      assertThat(token).isNotNull();
      assertThat(token.getSubject()).isEqualTo("fakeSub");
      assertThat(token.getIssuer()).isNotEmpty();
      assertThat(token.getOtherClaims())
          .containsEntry("acr", "eidas2");
    }
  }

  @Nested
  class IdTokenInformationExtraction {

    @BeforeEach
    void setup() throws IOException {
      var httpResponse = ClosableHttpResponse.from(
          Map.of(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON),
          USERINFO_JWT.toString()
      );

      when(httpClient.execute(any()))
          .thenAnswer(answer -> httpResponse);
    }

    @Test
    void id_token_acr_claim_should_match_with_selected_eidas_level_from_admin_interface() {
      var kid = "RSA-KID";
      var opaqueAccessToken = "2b3ea2e8-2d11-49a4-a369-5fb98d9d5315";
      var signedIdToken = givenAnRSASignedEidas2JWTWithRegisteredKidInJWKS(kid, publicKeysStore);

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
    void should_throw_exception_when_id_token_acr_claim_does_not_match_with_the_selected_eidas_level_from_admin_interface() {
      var kid = "RSA-KID";
      var opaqueAccessToken = "2b3ea2e8-2d11-49a4-a369-5fb98d9d5315";
      var signedIdTokenWithEidas1 = givenAnRSASignedJWTWithRegisteredKidInJWKS(kid, EIDAS1_JWT, publicKeysStore);

      var tokenEndpointResponse = generateTokenEndpointResponse(opaqueAccessToken, signedIdTokenWithEidas1);

      assertThatThrownBy(() -> provider.getFederatedIdentity(tokenEndpointResponse))
          .isInstanceOf(IdentityBrokerException.class)
          .hasMessage("The returned eIDAS level is insufficient");
    }

    @Test
    void should_throw_exception_when_id_token_does_not_contains_acr_claim() {
      var kid = "RSA-KID";
      var opaqueAccessToken = "2b3ea2e8-2d11-49a4-a369-5fb98d9d5315";
      var signedIdTokenWithoutEidasLevel = givenAnRSASignedJWTWithRegisteredKidInJWKS(kid, NO_EIDAS_LEVEL_JWT, publicKeysStore);

      var tokenEndpointResponse = generateTokenEndpointResponse(opaqueAccessToken, signedIdTokenWithoutEidasLevel);

      assertThatThrownBy(() -> provider.getFederatedIdentity(tokenEndpointResponse))
          .isInstanceOf(IdentityBrokerException.class)
          .hasMessage("The returned eIDAS level cannot be retrieved");
    }

    @Test
    void should_throw_exception_when_id_token_contains_acr_claim_who_does_not_match_with_a_supported_eidas_level() {
      var kid = "RSA-KID";
      var opaqueAccessToken = "2b3ea2e8-2d11-49a4-a369-5fb98d9d5315";
      var signedIdTokenWithoutEidasLevel = givenAnRSASignedJWTWithRegisteredKidInJWKS(kid, UNSUPPORTED_EIDAS_LEVEL_JWT, publicKeysStore);

      var tokenEndpointResponse = generateTokenEndpointResponse(opaqueAccessToken, signedIdTokenWithoutEidasLevel);

      assertThatThrownBy(() -> provider.getFederatedIdentity(tokenEndpointResponse))
          .isInstanceOf(IdentityBrokerException.class)
          .hasMessage("The returned eIDAS level cannot be retrieved");
    }
  }
}
