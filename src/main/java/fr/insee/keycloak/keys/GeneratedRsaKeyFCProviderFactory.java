package fr.insee.keycloak.keys;

import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.keys.AbstractRsaKeyProviderFactory;
import org.keycloak.keys.Attributes;
import org.keycloak.keys.GeneratedRsaKeyProviderFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public final class GeneratedRsaKeyFCProviderFactory extends GeneratedRsaKeyProviderFactory {

  public static final String ID = "rsa-generated-fc+";

  private static final ProviderConfigProperty RS_ALGORITHM_PROPERTY = new ProviderConfigProperty("algorithm", "Algorithm",
      "Intended algorithm for the key", ProviderConfigProperty.LIST_TYPE, "RSA-OAEP", "RSA-OAEP");

  private static List<ProviderConfigProperty> configProperties;

  @Override
  public String getId() {
    return ID;
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    // Add ECDSA Provider
    // load org.keycloak.crypto.def.DefaultCryptoProvider
    CryptoIntegration.init(GeneratedRsaKeyFCProviderFactory.class.getClassLoader());
    configProperties = AbstractRsaKeyProviderFactory.configurationBuilder()
      .property(Attributes.KEY_SIZE_PROPERTY.get())
        .property(Attributes.KEY_USE_PROPERTY)
        .build();
    configProperties.removeIf(p -> p.getName().equals("algorithm"));
    configProperties.add(RS_ALGORITHM_PROPERTY);

    return configProperties;
  }
}
