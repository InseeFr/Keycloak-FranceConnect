package fr.insee.keycloak.provider;

import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.broker.social.SocialIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;

public class FranceConnectIdentityProviderFactory extends AbstractIdentityProviderFactory<FranceConnectIdentityProvider>
        implements SocialIdentityProviderFactory<FranceConnectIdentityProvider> {

    public static final String FC_PROVIDER_ID = "franceconnect-particulier";
    public static final String FC_PROVIDER_NAME = "France Connect Particulier";

    public static final String[] COMPATIBLE_PROVIDER = new String[]{ FC_PROVIDER_ID };

    @Override
    public String getName() {
        return FC_PROVIDER_NAME;
    }

    @Override
    public String getId() {
        return FC_PROVIDER_ID;
    }

    @Override
    public FranceConnectIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
        return new FranceConnectIdentityProvider(
            session,
            new FranceConnectIdentityProviderConfig(model)
        );
    }

}
