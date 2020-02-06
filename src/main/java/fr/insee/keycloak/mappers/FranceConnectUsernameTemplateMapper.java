package fr.insee.keycloak.mappers;

import fr.insee.keycloak.provider.FranceConnectIdentityProviderFactory;
import org.keycloak.broker.oidc.mappers.UsernameTemplateMapper;

public class FranceConnectUsernameTemplateMapper extends UsernameTemplateMapper {

    private static final String MAPPER_NAME = "franceconnect-username-template-mapper";

    @Override
    public String[] getCompatibleProviders() {
        return FranceConnectIdentityProviderFactory.COMPATIBLE_PROVIDER;
    }

    @Override
    public String getId() {
        return MAPPER_NAME;
    }

}
