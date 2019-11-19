package fr.insee.keycloak;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;

import org.jboss.logging.Logger;
import org.keycloak.broker.oidc.OIDCIdentityProvider;
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.crypto.HMACProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.services.ErrorPage;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.resources.IdentityBrokerService;
import org.keycloak.services.resources.RealmsResource;

public class FranceConnectIdentityProvider extends OIDCIdentityProvider
    implements SocialIdentityProvider<OIDCIdentityProviderConfig> {

  private static final Logger log = Logger.getLogger(FranceConnectIdentityProvider.class);
	  
  protected String authorizationUrl;
  protected String tokenUrl;
  protected String userInfoUrl;
  protected String logoutUrl;


  public FranceConnectIdentityProvider(KeycloakSession session, FranceConnectIdentityProviderConfig config) {
    super(session, config);
    

  }

  protected void init() {
    this.getConfig().setAuthorizationUrl(getAuthorizationUrl());
    this.getConfig().setTokenUrl(getTokenUrl());
    this.getConfig().setUserInfoUrl(getUserInfoUrl());
    this.getConfig().setLogoutUrl(getLogoutUrl());
    this.getConfig().setValidateSignature(true);
    this.getConfig().setBackchannelSupported(false);
  }


  @Override
    public Object callback(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {
      
      return new OIDCEndpoint(callback, realm, event, (FranceConnectIdentityProviderConfig)getConfig());
    }

    protected class OIDCEndpoint extends Endpoint {
        FranceConnectIdentityProviderConfig config;

        public OIDCEndpoint(AuthenticationCallback callback, RealmModel realm, EventBuilder event, FranceConnectIdentityProviderConfig config) {
            super(callback, realm, event);
            this.config = config;
        }


        @GET
        @Path("logout_response")
        public Response logoutResponse(@QueryParam("state") String state) {
            UserSessionModel userSession;
            if(state == null){
              logger.error("state not found in query string");
              if (config.isIgnoreAbsentStateParameterLogout()){
                logger.warn("Using usersession from cookie");
                AuthenticationManager.AuthResult authResult = AuthenticationManager.authenticateIdentityCookie(session, realm, false);
                if(authResult!=null){
                  userSession = authResult.getSession();
                }else{
                  logger.error("no valid user session");
                  EventBuilder event = new EventBuilder(realm, session, clientConnection);
                  event.event(EventType.LOGOUT);
                  event.error(Errors.USER_SESSION_NOT_FOUND);
                  return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
                 }
              }else{
                EventBuilder event = new EventBuilder(realm, session, clientConnection);
                event.event(EventType.LOGOUT);
                event.error(Errors.USER_SESSION_NOT_FOUND);
                return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
              }
            }else{
              userSession = session.sessions().getUserSession(realm, state);
              if (userSession == null) {
                  logger.error("no valid user session");
                  EventBuilder event = new EventBuilder(realm, session, clientConnection);
                  event.event(EventType.LOGOUT);
                  event.error(Errors.USER_SESSION_NOT_FOUND);
                  return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
              }
              if (userSession.getState() != UserSessionModel.State.LOGGING_OUT) {
                  logger.error("usersession in different state");
                  EventBuilder event = new EventBuilder(realm, session, clientConnection);
                  event.event(EventType.LOGOUT);
                  event.error(Errors.USER_SESSION_NOT_FOUND);
                  return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, Messages.SESSION_NOT_ACTIVE);
              }
            }
            return AuthenticationManager.finishBrowserLogout(session, realm, userSession, session.getContext().getUri(), clientConnection, headers);
        }

    }



  
  @Override
  protected UriBuilder createAuthorizationUrl(AuthenticationRequest request)
  {
    UriBuilder uriBuilder = super.createAuthorizationUrl(request);
    FranceConnectIdentityProviderConfig fCConfig = (FranceConnectIdentityProviderConfig)getConfig();
    uriBuilder.queryParam("acr_values", new Object[] { fCConfig.getAcrValues() });
    logger.debugv("FranceConnect Authorization Url: {0}", uriBuilder.toString());
    return uriBuilder;
  }
  
  @Override
  public Response keycloakInitiatedBrowserLogout(KeycloakSession session,
      UserSessionModel userSession, UriInfo uriInfo, RealmModel realm) {
    if (getConfig().getLogoutUrl() == null || getConfig().getLogoutUrl().trim().equals("")) {
      return null;
    }
    String idToken = userSession.getNote(FEDERATED_ID_TOKEN);
    if (idToken != null && getConfig().isBackchannelSupported()) {
      backchannelLogout(userSession, idToken);
      return null;
    } else {
      String sessionId = userSession.getId();
      UriBuilder logoutUri =
          UriBuilder.fromUri(getConfig().getLogoutUrl()).queryParam("state", sessionId);
      if (idToken != null) {
        logoutUri.queryParam("id_token_hint", idToken);
      }
      String redirect =
          RealmsResource.brokerUrl(uriInfo).path(IdentityBrokerService.class, "getEndpoint")
              .path(OIDCEndpoint.class, "logoutResponse")
              .build(realm.getName(), getConfig().getAlias()).toString();
      logoutUri.queryParam("post_logout_redirect_uri", redirect);
      Response response = Response.status(302).location(logoutUri.build()).build();
      return response;
    }
  }


  @Override
  protected boolean verify(JWSInput jws) {
    if (!getConfig().isValidateSignature()) {
      return true;
    }
    return HMACProvider.verify(jws, getConfig().getClientSecret().getBytes());
  }

  public String getAuthorizationUrl() {
    return authorizationUrl;
  }


  public void setAuthorizationUrl(String authorizationUrl) {
    this.authorizationUrl = authorizationUrl;
  }


  public String getTokenUrl() {
    return tokenUrl;
  }


  public void setTokenUrl(String tokenUrl) {
    this.tokenUrl = tokenUrl;
  }


  public String getUserInfoUrl() {
    return userInfoUrl;
  }


  public void setUserInfoUrl(String userInfoUrl) {
    this.userInfoUrl = userInfoUrl;
  }


  public String getLogoutUrl() {
    return logoutUrl;
  }


  public void setLogoutUrl(String logoutUrl) {
    this.logoutUrl = logoutUrl;
  }



}
