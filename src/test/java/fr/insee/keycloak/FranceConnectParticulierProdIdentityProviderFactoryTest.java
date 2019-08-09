package fr.insee.keycloak;

import org.junit.Assert;
import org.junit.Test;

public class FranceConnectParticulierProdIdentityProviderFactoryTest {

  @Test
  public void testGetId() {
    Assert.assertEquals("franceconnect-particulier",
      new FranceConnectParticulierProdIdentityProviderFactory().getId());
  }

  @Test
  public void testGetName() {
    Assert.assertEquals("France Connect Particulier (Production)",
      new FranceConnectParticulierProdIdentityProviderFactory().getName());
  }
}
