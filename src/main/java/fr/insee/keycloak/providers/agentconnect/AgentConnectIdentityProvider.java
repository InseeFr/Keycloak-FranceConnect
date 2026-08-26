package fr.insee.keycloak.providers.agentconnect;

import fr.insee.keycloak.providers.common.AbstractBaseIdentityProvider;
import fr.insee.keycloak.providers.common.EidasLevel;
import fr.insee.keycloak.providers.common.Utils;
import jakarta.ws.rs.core.UriBuilder;
import org.keycloak.OAuth2Constants;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.models.KeycloakSession;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

final class AgentConnectIdentityProvider
    extends AbstractBaseIdentityProvider<AgentConnectIdentityProviderConfig> {

  static final String MFA_INSUFFICIENT_ACR_MESSAGE_KEY = "agentconnectMfaRequired";
  static final String MFA_INSUFFICIENT_ACR_ERROR_MESSAGE = "The returned ACR value is insufficient for MFA authentication";

  private static final List<String> ALL_MFA_ACR_VALUES = List.of(
      "eidas0-mfa",
      "eidas1-mfa",
      "eidas2",
      "eidas3"
  );

  AgentConnectIdentityProvider(KeycloakSession session, AgentConnectIdentityProviderConfig config) {
    super(session, config, Utils.getJsonWebKeySetFrom(config.getJwksUrl(), session));
  }

  @Override
  protected UriBuilder createAuthorizationUrl(AuthenticationRequest request) {
    var config = getConfig();
    UriBuilder uriBuilder;

    if (config.isMfaEnabled()) {
      // No acr_values — use claims parameter exclusively for MFA ACR negotiation.
      // Template expansion in build() percent-encodes the JSON value correctly.
      uriBuilder = UriBuilder.fromUri(
          super.createAuthorizationUrl(request)
              .queryParam("claims", "{claimsParam}")
              .build(buildMfaClaimsParam(getMfaAcrValuesFor(config.getEidasLevel())))
      );
    } else {
      request
          .getAuthenticationSession()
          .setClientNote(OAuth2Constants.ACR_VALUES, config.getEidasLevel().toString());
      uriBuilder = super.createAuthorizationUrl(request);
    }

    logger.debugv("AgentConnect Authorization Url: {0}", uriBuilder.build().toString());

    return uriBuilder;
  }

  @Override
  protected void validateAcrClaim(String acrClaim) {
    if (getConfig().isMfaEnabled()) {
      var acceptedValues = Set.copyOf(getMfaAcrValuesFor(getConfig().getEidasLevel()));
      if (!acceptedValues.contains(acrClaim)) {
        throw new IdentityBrokerException(MFA_INSUFFICIENT_ACR_ERROR_MESSAGE);
      }
    } else {
      super.validateAcrClaim(acrClaim);
    }
  }

  static List<String> getMfaAcrValuesFor(EidasLevel minLevel) {
    return switch (minLevel) {
      case EIDAS1 -> ALL_MFA_ACR_VALUES;
      case EIDAS2 -> List.of("eidas2", "eidas3");
      case EIDAS3 -> List.of("eidas3");
    };
  }

  private static String buildMfaClaimsParam(List<String> acrValues) {
    var values = acrValues.stream()
        .map(v -> "\"" + v + "\"")
        .collect(Collectors.joining(",", "[", "]"));
    return "{\"id_token\":{\"acr\":{\"essential\":true,\"values\":" + values + "}}}";
  }
}
