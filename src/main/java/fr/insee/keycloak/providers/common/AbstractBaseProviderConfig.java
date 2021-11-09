package fr.insee.keycloak.providers.common;

import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.models.IdentityProviderModel;

public abstract class AbstractBaseProviderConfig extends OIDCIdentityProviderConfig {

  protected AbstractBaseProviderConfig(IdentityProviderModel identityProviderModel) {
    super(identityProviderModel);
  }

  protected AbstractBaseProviderConfig() {
    super();
  }

  public boolean isIgnoreAbsentStateParameterLogout() {
    return Boolean.parseBoolean(getConfig().get("ignoreAbsentStateParameterLogout"));
  }

  public EidasLevel getEidasLevel() {
    return EidasLevel.getOrDefault(
        getConfig().get(EidasLevel.EIDAS_LEVEL_PROPERTY_NAME), getDefaultEidasLevel());
  }

  protected EidasLevel getDefaultEidasLevel() {
    return EidasLevel.EIDAS1;
  }
}
