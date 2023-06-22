package fr.insee.keycloak.providers.common;

import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.RealmModel;

import java.util.List;

import static java.util.Collections.emptyList;

public abstract class AbstractBaseProviderConfig extends OIDCIdentityProviderConfig {

  private static final String IS_CONFIG_CREATED_PROPERTY = "isCreated";

  protected AbstractBaseProviderConfig(IdentityProviderModel identityProviderModel) {
    super(identityProviderModel);
    initialize();
  }

  protected AbstractBaseProviderConfig() {
    super();
    initialize();
  }

  protected void initialize() {
    setUseJwksUrl(true);
    setValidateSignature(true);
    setBackchannelSupported(false);
  }

  protected List<IdentityProviderMapperModel> getDefaultMappers() {
    return emptyList();
  }

  public boolean isIgnoreAbsentStateParameterLogout() {
    // time to know if useful parameter
    return false;
    //return Boolean.parseBoolean(getConfig().get("ignoreAbsentStateParameterLogout"));
  }

  @Override
  public void validate(RealmModel realm) {
    super.validate(realm);

    if (!isCreated()) {
      getDefaultMappers().forEach(realm::addIdentityProviderMapper);
      getConfig().put(IS_CONFIG_CREATED_PROPERTY, "true");
    }
  }

  private boolean isCreated() {
    return Boolean.parseBoolean(getConfig().get(IS_CONFIG_CREATED_PROPERTY));
  }
}
