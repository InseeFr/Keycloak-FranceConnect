package fr.insee.keycloak.utils;

import jakarta.ws.rs.core.UriInfo;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.util.IdentityBrokerState;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public final class KeycloakFixture {

  public static final String CLIENT_ID = "fakeClientId";
  public static final String CLIENT_SECRET = "fakeClientSecretAtLeast256bitsNeededForHS";
  public static final String REDIRECT_URI = "http://localhost:8080/auth/realms/test/broker/franceconnect-particulier/endpoint";
  public static final String STATE_VALUE = "fakeState";
  public static final String DEFAULT_SCOPE = "openid";

  private KeycloakFixture() {
  }

  public static AuthenticationRequest givenAuthenticationRequest(KeycloakSession session) {

    var authenticationSessionModel = new MockAuthenticationSessionModel();
    var identityBrokerState = mock(IdentityBrokerState.class);

    when(identityBrokerState.getEncoded())
        .thenReturn(STATE_VALUE);

    return new AuthenticationRequest(
        session,
        mock(RealmModel.class),
        authenticationSessionModel,
        mock(HttpRequest.class),
        mock(UriInfo.class),
        identityBrokerState,
        REDIRECT_URI
    );
  }

}
