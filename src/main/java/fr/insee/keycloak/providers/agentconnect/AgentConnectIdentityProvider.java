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
import java.util.Map;
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

  // eidas0-mfa/eidas1-mfa only differ from eidas2/eidas3 by carrying their own eIDAS floor
  // (eidas2 and eidas3 already imply step-up per the eIDAS spec, hence no "-mfa" variant).
  private static final Map<String, EidasLevel> MFA_ACR_EIDAS_LEVELS = Map.of(
      "eidas0-mfa", EidasLevel.EIDAS1,
      "eidas1-mfa", EidasLevel.EIDAS1,
      "eidas2", EidasLevel.EIDAS2,
      "eidas3", EidasLevel.EIDAS3
  );

  AgentConnectIdentityProvider(KeycloakSession session, AgentConnectIdentityProviderConfig config) {
    super(session, config, Utils.getJsonWebKeySetFrom(config.getJwksUrl(), session));
  }

  @Override
  protected UriBuilder createAuthorizationUrl(AuthenticationRequest request) {
    var config = getConfig();
    var mfaRequirement = config.getMfaRequirement();
    UriBuilder uriBuilder;

    if (mfaRequirement == MfaRequirement.DISABLED) {
      request
          .getAuthenticationSession()
          .setClientNote(OAuth2Constants.ACR_VALUES, config.getEidasLevel().toString());
      uriBuilder = super.createAuthorizationUrl(request);
    } else {
      // No acr_values — use claims parameter exclusively for MFA ACR negotiation.
      // Template expansion in build() percent-encodes the JSON value correctly.
      var essential = mfaRequirement == MfaRequirement.REQUIRED;
      uriBuilder = UriBuilder.fromUri(
          super.createAuthorizationUrl(request)
              .queryParam("claims", "{claimsParam}")
              .build(buildMfaClaimsParam(getMfaAcrValuesFor(config.getEidasLevel()), essential))
      );
    }

    logger.debugv("AgentConnect Authorization Url: {0}", uriBuilder.build().toString());

    return uriBuilder;
  }

  @Override
  protected void validateAcrClaim(String acrClaim) {
    var mfaLevel = acrClaim == null ? null : MFA_ACR_EIDAS_LEVELS.get(acrClaim);

    // An MFA-backed ACR is always accepted once it meets the configured eIDAS floor, regardless
    // of the MFA requirement mode: a user who did complete MFA should never be turned away.
    if (mfaLevel != null && mfaLevel.compareTo(getConfig().getEidasLevel()) >= 0) {
      return;
    }

    if (getConfig().getMfaRequirement() == MfaRequirement.REQUIRED) {
      throw new IdentityBrokerException(MFA_INSUFFICIENT_ACR_ERROR_MESSAGE);
    }

    // DISABLED and OPTIONAL never hard-block a login solely for lacking MFA: fall back to the
    // regular (non-MFA) eIDAS level check so users who don't need 2FA still succeed.
    super.validateAcrClaim(acrClaim);
  }

  static List<String> getMfaAcrValuesFor(EidasLevel minLevel) {
    return switch (minLevel) {
      case EIDAS1 -> ALL_MFA_ACR_VALUES;
      case EIDAS2 -> List.of("eidas2", "eidas3");
      case EIDAS3 -> List.of("eidas3");
    };
  }

  private static String buildMfaClaimsParam(List<String> acrValues, boolean essential) {
    var values = acrValues.stream()
        .map(v -> "\"" + v + "\"")
        .collect(Collectors.joining(",", "[", "]"));
    return "{\"id_token\":{\"acr\":{\"essential\":" + essential + ",\"values\":" + values + "}}}";
  }
}
