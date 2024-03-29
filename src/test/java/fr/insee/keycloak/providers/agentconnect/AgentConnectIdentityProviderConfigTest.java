package fr.insee.keycloak.providers.agentconnect;

import fr.insee.keycloak.providers.common.EidasLevel;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator.ReplaceUnderscores;
import org.junit.jupiter.api.Test;
import org.keycloak.models.RealmModel;

import static fr.insee.keycloak.providers.agentconnect.ACFixture.givenConfigForIntegrationAndEidasLevel2;
import static fr.insee.keycloak.providers.agentconnect.ACFixture.givenConfigWithSelectedEnvAndSelectedEidasLevel;
import static fr.insee.keycloak.providers.agentconnect.AgentConnectIdentityProviderFactory.AC_PROVIDER_MAPPERS;
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

    verify(realm, times(AC_PROVIDER_MAPPERS.size())).addIdentityProviderMapper(any());

    var alreadySavedConfig = givenConfigForIntegrationAndEidasLevel2();
    var unusedRealm = mock(RealmModel.class);
    alreadySavedConfig.getConfig().put("isCreated", "true");

    alreadySavedConfig.validate(unusedRealm);

    verify(unusedRealm, never()).addIdentityProviderMapper(any());
  }
}
