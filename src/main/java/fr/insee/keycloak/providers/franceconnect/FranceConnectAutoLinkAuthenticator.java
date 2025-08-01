package fr.insee.keycloak.providers.franceconnect;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.broker.AbstractIdpAuthenticator;
import org.keycloak.authentication.authenticators.broker.util.ExistingUserInfo;
import org.keycloak.authentication.authenticators.broker.util.SerializedBrokeredIdentityContext;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static java.util.Map.entry;

public class FranceConnectAutoLinkAuthenticator extends AbstractIdpAuthenticator {

  private static final Logger logger = Logger.getLogger(FranceConnectAutoLinkAuthenticator.class);

  public FranceConnectAutoLinkAuthenticator() {
  }

  protected void actionImpl(AuthenticationFlowContext context, SerializedBrokeredIdentityContext serializedCtx, BrokeredIdentityContext brokerCtx) {
  }

  protected void authenticateImpl(AuthenticationFlowContext context, SerializedBrokeredIdentityContext serializedCtx, BrokeredIdentityContext brokerCtx) {
    KeycloakSession session = context.getSession();
    RealmModel realm = context.getRealm();

    // IDP mappers: FranceConnect claims → Keycloak user attributes
    Map<String, String> attributeMapping = session.identityProviders().getMappersByAliasStream(brokerCtx.getIdpConfig().getAlias())
        .filter(m -> m.getConfig().containsKey("claim") && m.getConfig().containsKey("user.attribute"))
        .map(m -> entry(m.getConfig().get("claim"), m.getConfig().get("user.attribute")))
        .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));

    // FranceConnect identity
    IdentitePivot identitePivot = new IdentitePivot(attributeMapping, brokerCtx.getAttributes());

    ExistingUserInfo matchingUser = this.checkMatchingUser(context, identitePivot);
    if (matchingUser != null) {
      // Found a Keycloak user matching the FranceConnect identity.
      context.getAuthenticationSession().setAuthNote(EXISTING_USER_INFO, matchingUser.serialize());
      UserModel user = getExistingUser(session, realm, context.getAuthenticationSession());
      context.setUser(user);
      context.success();
    } else {
      // No matching Keycloak users.
      // Continue the authentication flow.
      context.attempted();
    }
  }

  /**
   * {@return Keycloak account matching the FranceConnect identity} {@code null} if no match
   */
  protected ExistingUserInfo checkMatchingUser(AuthenticationFlowContext context, IdentitePivot identitePivot) {
    if (identitePivot == null) {
      return null;
    }

    HashMap<String, String> searchParameters = new HashMap<>(Map.of(UserModel.ENABLED, "true", UserModel.EXACT, "true"));
    searchParameters.putAll(identitePivot.toMap());

    List<UserModel> users = context.getSession().users().searchForUserStream(context.getRealm(), searchParameters).toList();
    if (users.isEmpty()) {
      logger.debugf("No Keycloak account match the FranceConnect identity %s", identitePivot);
      return null;
    } else if (users.size() == 1) {
      UserModel existingUser = users.get(0);
      logger.debugf("User %s matches the FranceConnect identity %s", existingUser.getId(), identitePivot);
      return new ExistingUserInfo(existingUser.getId(), UserModel.USERNAME, existingUser.getEmail());
    } else {
      // This should not happen!
      logger.warnf("More than one Keycloak accounts match the FranceConnect identity %s", identitePivot);
      return null;
    }
  }

  @Override
  public boolean requiresUser() {
    return false;
  }

  @Override
  public boolean configuredFor(KeycloakSession keycloakSession, RealmModel realmModel, UserModel userModel) {
    return true;
  }
}
