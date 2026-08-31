package fr.insee.keycloak.providers.agentconnect;

import fr.insee.keycloak.providers.common.EidasLevel;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator.ReplaceUnderscores;
import org.junit.jupiter.api.Test;
import org.keycloak.models.RealmModel;

import static fr.insee.keycloak.providers.agentconnect.ACFixture.givenConfigForIntegrationAndEidasLevel2;
import static fr.insee.keycloak.providers.agentconnect.ACFixture.givenConfigWithLegacyMfaEnabled;
import static fr.insee.keycloak.providers.agentconnect.ACFixture.givenConfigWithMfaRequirementAndEidasLevel;
import static fr.insee.keycloak.providers.agentconnect.ACFixture.givenConfigWithSelectedEnvAndSelectedEidasLevel;
import static fr.insee.keycloak.providers.agentconnect.AgentConnectIdentityProviderFactory.getAcProviderMappers;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@DisplayNameGeneration(ReplaceUnderscores.class)
class AgentConnectIdentityProviderConfigTest {

  @Test
  void should_initialize_config_with_selected_eidas_level_from_admin_interface() {
    var config = givenConfigWithSelectedEnvAndSelectedEidasLevel(
        "integration_rie", "eidas1"
    );

    assertThat(config.getEidasLevel()).isEqualTo(EidasLevel.EIDAS1);

    config = givenConfigWithSelectedEnvAndSelectedEidasLevel(
        "integration_rie", "eidas2"
    );

    assertThat(config.getEidasLevel()).isEqualTo(EidasLevel.EIDAS2);

    config = givenConfigWithSelectedEnvAndSelectedEidasLevel(
        "integration_rie", "eidas3"
    );

    assertThat(config.getEidasLevel()).isEqualTo(EidasLevel.EIDAS3);
  }

  @Test
  void should_initialize_config_with_url_properties_corresponding_to_selected_environment_from_admin_interface() {
    var config = givenConfigForIntegrationAndEidasLevel2();

    assertThat(config.getAuthorizationUrl()).isNotNull().endsWith("/authorize");
    assertThat(config.getTokenUrl()).isNotNull().endsWith("/token");
    assertThat(config.getUserInfoUrl()).isNotNull().endsWith("/userinfo");
    assertThat(config.getLogoutUrl()).isNotNull().endsWith("/session/end");
    assertThat(config.getIssuer()).isNotNull().endsWith("/api/v2");
    assertThat(config.isUseJwksUrl()).isTrue();
    assertThat(config.getJwksUrl()).isNotNull().endsWith("/jwks");
  }

  @Test
  void should_initialize_config_with_selected_ignoreAbsentStateParameterLogout_from_admin_interface() {
    var config = givenConfigForIntegrationAndEidasLevel2();

    assertThat(config.isIgnoreAbsentStateParameterLogout()).isFalse();
  }

  @Test
  void should_initialize_config_with_signature_validation() {
    var config = givenConfigForIntegrationAndEidasLevel2();

    assertThat(config.isValidateSignature()).isTrue();
  }

  @Test
  void should_initialize_config_without_backchannel_support() {
    var config = givenConfigForIntegrationAndEidasLevel2();

    assertThat(config.isBackchannelSupported()).isFalse();
  }

  @Test
  void should_create_identity_mappers_when_saving_configuration_for_the_first_time() {
    var unsavedConfig = givenConfigForIntegrationAndEidasLevel2();
    var realm = mock(RealmModel.class);

    unsavedConfig.validate(realm);

    verify(realm, times(getAcProviderMappers().size())).addIdentityProviderMapper(any());

    var alreadySavedConfig = givenConfigForIntegrationAndEidasLevel2();
    var unusedRealm = mock(RealmModel.class);
    alreadySavedConfig.getConfig().put("isCreated", "true");

    alreadySavedConfig.validate(unusedRealm);

    verify(unusedRealm, never()).addIdentityProviderMapper(any());
  }

  @Test
  void should_default_mfa_requirement_to_disabled_when_nothing_configured() {
    var config = givenConfigForIntegrationAndEidasLevel2();

    assertThat(config.getMfaRequirement()).isEqualTo(MfaRequirement.DISABLED);
  }

  @Test
  void should_read_legacy_mfa_enabled_true_as_required() {
    var config = givenConfigWithLegacyMfaEnabled("true");

    assertThat(config.getMfaRequirement()).isEqualTo(MfaRequirement.REQUIRED);
  }

  @Test
  void should_read_legacy_mfa_enabled_false_as_disabled() {
    var config = givenConfigWithLegacyMfaEnabled("false");

    assertThat(config.getMfaRequirement()).isEqualTo(MfaRequirement.DISABLED);
  }

  @Test
  void should_prefer_mfa_mode_property_over_legacy_mfa_enabled_when_both_are_present() {
    var config = givenConfigWithMfaRequirementAndEidasLevel(MfaRequirement.OPTIONAL, EidasLevel.EIDAS1.toString());
    config.getConfig().put(AgentConnectIdentityProviderConfig.LEGACY_MFA_ENABLED_PROPERTY_NAME, "true");

    assertThat(config.getMfaRequirement()).isEqualTo(MfaRequirement.OPTIONAL);
  }
}
