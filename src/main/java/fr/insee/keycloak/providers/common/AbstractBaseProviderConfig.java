package fr.insee.keycloak.providers.common;

import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.models.IdentityProviderModel;

public abstract class AbstractBaseProviderConfig extends OIDCIdentityProviderConfig {

  protected AbstractBaseProviderConfig(IdentityProviderModel identityProviderModel) {
    super(identityProviderModel);
    initialize();
  }

  protected AbstractBaseProviderConfig() {
    super();
    initialize();
  }

  protected abstract String getEnvironmentProperty(String key);

  protected void initialize() {
    configureUrlsFromEnvironment();

    setValidateSignature(true);
    setBackchannelSupported(false);
  }

  protected void configureUrlsFromEnvironment() {
    setAuthorizationUrl(getEnvironmentProperty("authorization.url"));
    setTokenUrl(getEnvironmentProperty("token.url"));
    setUserInfoUrl(getEnvironmentProperty("userinfo.url"));
    setLogoutUrl(getEnvironmentProperty("logout.url"));
    setIssuer(getEnvironmentProperty("issuer.url"));

    var useJwks = getEnvironmentProperty("use.jwks.url");
    if (useJwks != null) {
      setJwksUrl(getEnvironmentProperty("jwks.url"));
      setUseJwksUrl(Boolean.parseBoolean(useJwks));
    }
  }

  protected EidasLevel getDefaultEidasLevel() {
    return EidasLevel.EIDAS1;
  }

  public boolean isIgnoreAbsentStateParameterLogout() {
    return Boolean.parseBoolean(getConfig().get("ignoreAbsentStateParameterLogout"));
  }

  public EidasLevel getEidasLevel() {
    return EidasLevel.getOrDefault(
        getConfig().get(EidasLevel.EIDAS_LEVEL_PROPERTY_NAME),
        getDefaultEidasLevel()
    );
  }
}
