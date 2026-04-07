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
  }

  protected AbstractBaseProviderConfig() {
    super();
  }

  protected abstract String getEnvironmentProperty(String key);

  @Override
  public String getAuthorizationUrl() {
    return getEnvironmentProperty("authorization.url");
  }

  @Override
  public String getTokenUrl() {
    return getEnvironmentProperty("token.url");
  }

  @Override
  public String getUserInfoUrl() {
    return getEnvironmentProperty("userinfo.url");
  }

  @Override
  public String getLogoutUrl() {
    return getEnvironmentProperty("logout.url");
  }

  @Override
  public String getIssuer() {
    return getEnvironmentProperty("issuer.url");
  }

  @Override
  public boolean isUseJwksUrl() {
    return Boolean.parseBoolean(getEnvironmentProperty("use.jwks.url"));
  }

  @Override
  public String getJwksUrl() {
   return getEnvironmentProperty("jwks.url");
  }

  @Override
  public boolean isValidateSignature() {
    return true;
  }

  @Override
  public boolean isBackchannelSupported() {
    return false;
  }

  protected EidasLevel getDefaultEidasLevel() {
    return EidasLevel.EIDAS1;
  }

  protected List<IdentityProviderMapperModel> getDefaultMappers() {
    return emptyList();
  }

  public boolean isIgnoreAbsentStateParameterLogout() {
    return Boolean.parseBoolean(getConfig().get("ignoreAbsentStateParameterLogout"));
  }

  @Override
  public void validate(RealmModel realm) {
    super.validate(realm);

    if (!isCreated()) {
      getDefaultMappers().forEach(realm::addIdentityProviderMapper);
      getConfig().put(IS_CONFIG_CREATED_PROPERTY, "true");
    }
  }

  public EidasLevel getEidasLevel() {
    return EidasLevel.getOrDefault(
        getConfig().get(EidasLevel.EIDAS_LEVEL_PROPERTY_NAME),
        getDefaultEidasLevel()
    );
  }

  private boolean isCreated() {
    return Boolean.parseBoolean(getConfig().get(IS_CONFIG_CREATED_PROPERTY));
  }
}
