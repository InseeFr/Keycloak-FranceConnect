package fr.insee.keycloak.providers.agentconnect;

import fr.insee.keycloak.providers.common.EidasLevel;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator.ReplaceUnderscores;
import org.junit.jupiter.api.Test;
import org.keycloak.models.RealmModel;

import static fr.insee.keycloak.providers.agentconnect.ACFixture.givenConfig;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@DisplayNameGeneration(ReplaceUnderscores.class)
class AgentConnectIdentityProviderConfigTest {

  public static int NUMBER_DEFAULT_MAPPER = 4;

//  @Test
//  void should_initialize_config_with_selected_ignoreAbsentStateParameterLogout_from_admin_interface() {
//    var config = givenConfigForIntegrationAndEidasLevel2();
//
//    assertThat(config.isIgnoreAbsentStateParameterLogout()).isFalse();
//  }

  @Test
  void should_initialize_config_with_signature_validation() {
    var config = givenConfig();

    assertThat(config.isValidateSignature()).isTrue();
  }

  @Test
  void should_initialize_config_without_backchannel_support() {
    var config = givenConfig();

    assertThat(config.isBackchannelSupported()).isFalse();
  }

  @Test
  void should_create_identity_mappers_when_saving_configuration_for_the_first_time() {
    var unsavedConfig = givenConfig();
    var realm = mock(RealmModel.class);

    unsavedConfig.validate(realm);

    verify(realm, times(NUMBER_DEFAULT_MAPPER)).addIdentityProviderMapper(any());

    var alreadySavedConfig = givenConfig();
    var unusedRealm = mock(RealmModel.class);
    alreadySavedConfig.getConfig().put("isCreated", "true");

    alreadySavedConfig.validate(unusedRealm);

    verify(unusedRealm, never()).addIdentityProviderMapper(any());
  }
}
