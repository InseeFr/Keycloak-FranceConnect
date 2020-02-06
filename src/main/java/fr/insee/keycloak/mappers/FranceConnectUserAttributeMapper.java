package fr.insee.keycloak.mappers;

import fr.insee.keycloak.provider.FranceConnectIdentityProviderFactory;
import org.keycloak.broker.oidc.mappers.UserAttributeMapper;

public class FranceConnectUserAttributeMapper extends UserAttributeMapper {

    private static final String MAPPER_NAME = "franceconnect-user-attribute-mapper";

    @Override
    public String[] getCompatibleProviders() {
        return FranceConnectIdentityProviderFactory.COMPATIBLE_PROVIDER;
    }

    @Override
    public String getId() {
        return MAPPER_NAME;
    }

}
