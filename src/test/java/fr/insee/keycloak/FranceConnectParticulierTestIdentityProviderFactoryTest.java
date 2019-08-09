package fr.insee.keycloak;

import org.junit.Assert;
import org.junit.Test;

public class FranceConnectParticulierTestIdentityProviderFactoryTest {

  @Test
  public void testGetId() {
    Assert.assertEquals("franceconnect-particulier-test",
      new FranceConnectParticulierTestIdentityProviderFactory().getId());
  }

  @Test
  public void testGetName() {
    Assert.assertEquals("France Connect Particulier (Integration)",
      new FranceConnectParticulierTestIdentityProviderFactory().getName());
  }
}
