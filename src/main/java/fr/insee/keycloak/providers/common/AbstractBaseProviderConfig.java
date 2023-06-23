package fr.insee.keycloak.providers.common;

import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.RealmModel;

import java.security.Provider;
import java.util.List;

import static java.util.Collections.emptyList;

public abstract class AbstractBaseProviderConfig extends OIDCIdentityProviderConfig {

  private static final String IS_CONFIG_CREATED_PROPERTY = "isCreated";

  protected final String providerID;
  protected final Environment environment;

  protected AbstractBaseProviderConfig(IdentityProviderModel identityProviderModel,Environment environment, String providerID) {
    super(identityProviderModel);
    this.providerID = providerID;
    this.environment = environment;
    initialize();
  }

  protected AbstractBaseProviderConfig(Environment environment, String providerID) {
    super();
    this.providerID = providerID;
    this.environment = environment;
    initialize();
  }

  protected String getEnvironmentProperty(String key){
    return environment.getProperty(key);
  }

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

  protected List<IdentityProviderMapperModel> getDefaultMappers() {
    return emptyList();
  }

  public boolean isIgnoreAbsentStateParameterLogout() {
    // TODO still useful ??
    //return Boolean.parseBoolean(getConfig().get("ignoreAbsentStateParameterLogout"));
    return false;
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
