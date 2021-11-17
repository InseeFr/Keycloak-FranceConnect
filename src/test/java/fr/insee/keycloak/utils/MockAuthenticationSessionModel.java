package fr.insee.keycloak.utils;

import org.keycloak.models.ClientModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * Creates a fake implementation of AuthenticationSessionModel with clientNotes map
 */
public final class MockAuthenticationSessionModel implements AuthenticationSessionModel {

  private final Map<String, String> clientNotes = new HashMap<>();

  @Override
  public String getTabId() {
    return null;
  }

  @Override
  public RootAuthenticationSessionModel getParentSession() {
    return null;
  }

  @Override
  public Map<String, ExecutionStatus> getExecutionStatus() {
    return null;
  }

  @Override
  public void setExecutionStatus(String authenticator, ExecutionStatus status) {

  }

  @Override
  public void clearExecutionStatus() {

  }

  @Override
  public UserModel getAuthenticatedUser() {
    return null;
  }

  @Override
  public void setAuthenticatedUser(UserModel user) {

  }

  @Override
  public Set<String> getRequiredActions() {
    return null;
  }

  @Override
  public void addRequiredAction(String action) {

  }

  @Override
  public void removeRequiredAction(String action) {

  }

  @Override
  public void addRequiredAction(UserModel.RequiredAction action) {

  }

  @Override
  public void removeRequiredAction(UserModel.RequiredAction action) {

  }

  @Override
  public void setUserSessionNote(String name, String value) {

  }

  @Override
  public Map<String, String> getUserSessionNotes() {
    return null;
  }

  @Override
  public void clearUserSessionNotes() {

  }

  @Override
  public String getAuthNote(String name) {
    return null;
  }

  @Override
  public void setAuthNote(String name, String value) {

  }

  @Override
  public void removeAuthNote(String name) {

  }

  @Override
  public void clearAuthNotes() {

  }

  @Override
  public String getClientNote(String name) {
    return clientNotes.get(name);
  }

  @Override
  public void setClientNote(String name, String value) {
    clientNotes.put(name, value);
  }

  @Override
  public void removeClientNote(String name) {
    clientNotes.remove(name);
  }

  @Override
  public Map<String, String> getClientNotes() {
    return clientNotes;
  }

  @Override
  public void clearClientNotes() {
    clientNotes.clear();
  }

  @Override
  public Set<String> getClientScopes() {
    return null;
  }

  @Override
  public void setClientScopes(Set<String> clientScopes) {

  }

  @Override
  public String getRedirectUri() {
    return null;
  }

  @Override
  public void setRedirectUri(String uri) {

  }

  @Override
  public RealmModel getRealm() {
    return null;
  }

  @Override
  public ClientModel getClient() {
    return null;
  }

  @Override
  public String getAction() {
    return null;
  }

  @Override
  public void setAction(String action) {

  }

  @Override
  public String getProtocol() {
    return null;
  }

  @Override
  public void setProtocol(String method) {

  }
}
