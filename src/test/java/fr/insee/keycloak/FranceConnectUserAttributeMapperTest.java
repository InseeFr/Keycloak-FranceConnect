package fr.insee.keycloak;

import org.junit.Assert;
import org.junit.Test;

public class FranceConnectUserAttributeMapperTest {

  @Test
  public void testGetCompatibleProviders() {
    Assert.assertArrayEquals(
      new String[] {"franceconnect-particulier", "franceconnect-particulier-test"},
      new FranceConnectUserAttributeMapper().getCompatibleProviders());
  }

  @Test
  public void testGetId() {
    Assert.assertEquals("franceconnect-user-attribute-mapper",
      new FranceConnectUserAttributeMapper().getId());
  }
}
