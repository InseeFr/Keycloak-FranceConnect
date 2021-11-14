package fr.insee.keycloak.providers.franceconnect;

import fr.insee.keycloak.providers.common.EidasLevel;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator.ReplaceUnderscores;
import org.junit.jupiter.api.Test;

import static fr.insee.keycloak.providers.franceconnect.FCFixture.givenConfigForIntegrationAndEidasLevel2;
import static fr.insee.keycloak.providers.franceconnect.FCFixture.givenConfigWithSelectedEnvAndSelectedEidasLevel;
import static org.assertj.core.api.Assertions.assertThat;

@DisplayNameGeneration(ReplaceUnderscores.class)
class FranceConnectIdentityProviderConfigTest {

  @Test
  void should_initialize_config_with_selected_eidas_level_from_admin_interface() {
    var config = givenConfigWithSelectedEnvAndSelectedEidasLevel(
        "integration_v1", "eidas1"
    );

    assertThat(config.getEidasLevel()).isEqualTo(EidasLevel.EIDAS1);

    config = givenConfigWithSelectedEnvAndSelectedEidasLevel(
        "integration_v1", "eidas2"
    );

    assertThat(config.getEidasLevel()).isEqualTo(EidasLevel.EIDAS2);

    config = givenConfigWithSelectedEnvAndSelectedEidasLevel(
        "integration_v1", "eidas3"
    );

    assertThat(config.getEidasLevel()).isEqualTo(EidasLevel.EIDAS3);
  }

  @Test
  void should_initialize_config_with_url_properties_corresponding_to_selected_environment_from_admin_interface() {
    var config = givenConfigForIntegrationAndEidasLevel2();

    assertThat(config.getAuthorizationUrl()).isNotNull().endsWith("/authorize");
    assertThat(config.getTokenUrl()).isNotNull().endsWith("/token");
    assertThat(config.getUserInfoUrl()).isNotNull().endsWith("/userinfo");
    assertThat(config.getLogoutUrl()).isNotNull().endsWith("/logout");
    assertThat(config.getIssuer()).isNotNull();
    assertThat(config.isUseJwksUrl()).isTrue();
    assertThat(config.getJwksUrl()).endsWith("/jwks");
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
}