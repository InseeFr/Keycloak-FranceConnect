package fr.insee.keycloak.providers.franceconnect;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.broker.AbstractIdpAuthenticator;
import org.keycloak.authentication.authenticators.broker.util.ExistingUserInfo;
import org.keycloak.authentication.authenticators.broker.util.SerializedBrokeredIdentityContext;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

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
      .filter(m -> IdentitePivot.DEFAULT_CLAIMS.contains(m.getConfig().get("claim")))
      .collect(Collectors.toMap(
          m -> m.getConfig().get("claim"),
          m -> m.getConfig().get("user.attribute")
      ));

    // FranceConnect identity
    IdentitePivot identitePivot = new IdentitePivot(attributeMapping, brokerCtx.getAttributes());

    ExistingUserInfo matchingUser = this.checkMatchingUser(context, brokerCtx, identitePivot);
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
  protected ExistingUserInfo checkMatchingUser(AuthenticationFlowContext context, BrokeredIdentityContext brokerCtx, IdentitePivot identitePivot) {
    KeycloakSession session = context.getSession();

    // FC claims used for account linking
    Set<String> accountLinkingClaims = Set.of(
        Constants.CFG_DELIMITER_PATTERN.split(
            session.identityProviders().getByAlias(brokerCtx.getIdpConfig().getAlias()).getConfig().get(IdentitePivot.ACCOUNT_LINKING_CLAIMS_PROPERTY_NAME)
        )
    );

    HashMap<String, String> searchParameters = new HashMap<>(Map.of(UserModel.ENABLED, "true", UserModel.EXACT, "true"));
    searchParameters.putAll(identitePivot.toMap(accountLinkingClaims));

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
