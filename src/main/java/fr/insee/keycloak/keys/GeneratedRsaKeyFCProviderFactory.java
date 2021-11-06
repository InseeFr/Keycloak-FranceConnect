package fr.insee.keycloak.keys;

import java.util.List;


import org.keycloak.crypto.Algorithm;
import org.keycloak.keys.AbstractRsaKeyProviderFactory;
import org.keycloak.keys.Attributes;
import org.keycloak.keys.GeneratedRsaKeyProviderFactory;
import org.keycloak.provider.ProviderConfigProperty;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class GeneratedRsaKeyFCProviderFactory extends GeneratedRsaKeyProviderFactory {

    public static final String ID = "rsa-generated-fc+";




    private static ProviderConfigProperty RS_ALGORITHM_PROPERTY = new ProviderConfigProperty("algorithm", "Algorithm",
            "Intended algorithm for the key", ProviderConfigProperty.LIST_TYPE, "RSA-OAEP", "RSA-OAEP");
    
    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = AbstractRsaKeyProviderFactory.configurationBuilder()
            .property(Attributes.KEY_SIZE_PROPERTY)
            .property(Attributes.KEY_USE_PROPERTY)
            .build();
            
    @Override
    public String getId() {
        return ID;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        CONFIG_PROPERTIES.removeIf(p -> p.getName().equals("algorithm"));
        CONFIG_PROPERTIES.add(RS_ALGORITHM_PROPERTY);
        return CONFIG_PROPERTIES;
    }

}
