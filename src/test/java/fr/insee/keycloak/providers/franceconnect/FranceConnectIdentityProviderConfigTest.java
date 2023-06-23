package fr.insee.keycloak.providers.franceconnect;

import static fr.insee.keycloak.providers.franceconnect.FCFixture.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import fr.insee.keycloak.providers.common.EidasLevel;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator.ReplaceUnderscores;
import org.junit.jupiter.api.Test;
import org.keycloak.models.RealmModel;

@DisplayNameGeneration(ReplaceUnderscores.class)
class FranceConnectIdentityProviderConfigTest {

  public static final int NUMBER_OF_DEFAULT_MAPPERS = 4;

  @Test
  void
      should_initialize_config_with_url_properties_corresponding_to_selected_environment_from_admin_interface() {
    var config = givenConfigWithSelectedEnv(FCEnvironment.INTEGRATION_V2);

    assertThat(config.getAuthorizationUrl()).isNotNull().endsWith("/authorize");
    assertThat(config.getTokenUrl()).isNotNull().endsWith("/token");
    assertThat(config.getUserInfoUrl()).isNotNull().endsWith("/userinfo");
    assertThat(config.getLogoutUrl()).isNotNull().endsWith("/session/end");
    assertThat(config.getIssuer()).isNotNull();
    assertThat(config.isUseJwksUrl()).isTrue();
    assertThat(config.getJwksUrl()).endsWith("/jwks");
  }

  @Test
  void
      should_initialize_config_with_selected_ignoreAbsentStateParameterLogout_from_admin_interface() {
    var config = givenConfigWithSelectedEnv(FCEnvironment.INTEGRATION_V2);

    assertThat(config.isIgnoreAbsentStateParameterLogout()).isFalse();
  }

  @Test
  void should_initialize_config_with_signature_validation() {
    var config = givenConfigWithSelectedEnv(FCEnvironment.INTEGRATION_V2);

    assertThat(config.isValidateSignature()).isTrue();
  }

  @Test
  void should_initialize_config_without_backchannel_support() {
    var config = givenConfigWithSelectedEnv(FCEnvironment.INTEGRATION_V2);

    assertThat(config.isBackchannelSupported()).isFalse();
  }

  @Test
  void should_create_identity_mappers_when_saving_configuration_for_the_first_time() {
    var unsavedConfig = givenConfigWithSelectedEnv(FCEnvironment.INTEGRATION_V2);
    var realm = mock(RealmModel.class);

    unsavedConfig.validate(realm);

    verify(realm, times(NUMBER_OF_DEFAULT_MAPPERS)).addIdentityProviderMapper(any());

    var alreadySavedConfig = givenConfigWithSelectedEnv(FCEnvironment.INTEGRATION_V2);
    var unusedRealm = mock(RealmModel.class);
    alreadySavedConfig.getConfig().put("isCreated", "true");

    alreadySavedConfig.validate(unusedRealm);

    verify(unusedRealm, never()).addIdentityProviderMapper(any());
  }
}
