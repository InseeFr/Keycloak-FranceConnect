package fr.insee.keycloak;

import org.junit.Assert;
import org.junit.Test;

public class FranceConnectUsernameTemplateMapperTest {

  @Test
  public void testGetCompatibleProviders() {
    Assert.assertArrayEquals(
      new String[] {"franceconnect-particulier", "franceconnect-particulier-test"},
      new FranceConnectUsernameTemplateMapper().getCompatibleProviders());
  }

  @Test
  public void testGetId() {
    Assert.assertEquals("franceconnect-username-template-mapper",
      new FranceConnectUsernameTemplateMapper().getId());
  }
}
