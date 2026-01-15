package fr.insee.keycloak.providers.franceconnect;

import fr.insee.keycloak.providers.common.EidasLevel;
import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.broker.social.SocialIdentityProviderFactory;
import org.keycloak.models.Constants;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static fr.insee.keycloak.providers.common.Utils.createHardcodedAttributeMapper;
import static fr.insee.keycloak.providers.common.Utils.createUserAttributeMapper;

public final class FranceConnectIdentityProviderFactory
    extends AbstractIdentityProviderFactory<FranceConnectIdentityProvider>
    implements SocialIdentityProviderFactory<FranceConnectIdentityProvider> {

  public static final String FC_PROVIDER_ID = "franceconnect-particulier";
  public static final String FC_PROVIDER_NAME = "France Connect Particulier";

  static final FCEnvironment DEFAULT_FC_ENVIRONMENT = FCEnvironment.INTEGRATION_V1;

  static final List<IdentityProviderMapperModel> FC_PROVIDER_MAPPERS = List.of(
      // https://docs.partenaires.franceconnect.gouv.fr/fi/general/donnees-utilisateur/#l-identite-pivot
      createUserAttributeMapper(FC_PROVIDER_ID, "firstName", IdentitePivot.CLAIM_GIVEN_NAME, "firstName"),
      createUserAttributeMapper(FC_PROVIDER_ID, "lastName", IdentitePivot.CLAIM_FAMILY_NAME, "lastName"),
      createUserAttributeMapper(FC_PROVIDER_ID, "gender", IdentitePivot.CLAIM_GENDER, "gender"),
      createUserAttributeMapper(FC_PROVIDER_ID, "birthdate", IdentitePivot.CLAIM_BIRTHDATE, "birthdate"),
      createUserAttributeMapper(FC_PROVIDER_ID, "birthplace", IdentitePivot.CLAIM_BIRTHPLACE, "birthplace"),
      createUserAttributeMapper(FC_PROVIDER_ID, "birthcountry", IdentitePivot.CLAIM_BIRTHCOUNTRY, "birthcountry"),

      // https://docs.partenaires.franceconnect.gouv.fr/fi/general/donnees-utilisateur/#les-donnees-complementaires
      createUserAttributeMapper(FC_PROVIDER_ID, "email", "email", "email"),

      // hardcoded
      createHardcodedAttributeMapper(FC_PROVIDER_ID, "provider", "provider", "FC")
  );

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
    return new FranceConnectIdentityProvider(session, new FranceConnectIdentityProviderConfig(model));
  }

  @Override
  public FranceConnectIdentityProviderConfig createConfig() {
    return new FranceConnectIdentityProviderConfig();
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    List<String> environments = Stream.of(FCEnvironment.values())
        .map(Enum::name)
        .collect(Collectors.toList());

    List<String> eidasLevels = Stream.of(EidasLevel.values())
        .map(Enum::name)
        .collect(Collectors.toList());

    return ProviderConfigurationBuilder.create()
        // Environment
        .property().name(FCEnvironment.ENVIRONMENT_PROPERTY_NAME)
        .label("Environnement FranceConnect")
        .helpText("Permet de choisir l'environnement FranceConnect. Effet : change les urls vers FranceConnect.")
        .type(ProviderConfigProperty.LIST_TYPE)
        .options(environments)
        .defaultValue(DEFAULT_FC_ENVIRONMENT)
        .add()
        // EIDAS level
        .property().name(EidasLevel.EIDAS_LEVEL_PROPERTY_NAME)
        .label("Niveau de garantie eIDAS")
        .helpText("Permet de fixer le niveau de garantie du compte utilisateur souhaité. Effet : désactive des fournisseurs d'identités (FI) sur la page de login FranceConnect.")
        .type(ProviderConfigProperty.LIST_TYPE)
        .options(eidasLevels)
        .defaultValue(EidasLevel.EIDAS1)
        .add()
        // Account linking: claims used for identity check
        .property().name(IdentitePivot.ACCOUNT_LINKING_CLAIMS_PROPERTY_NAME)
        .label("Champs pour la réconciliation auto")
        .helpText("Permet de sélectionner les champs de l'identité pivot utilisés pour la réconciliation automatique.")
        .type(ProviderConfigProperty.MULTIVALUED_LIST_TYPE)
        .options(IdentitePivot.DEFAULT_CLAIMS)
        .defaultValue(String.join(Constants.CFG_DELIMITER, IdentitePivot.DEFAULT_CLAIMS))
        .add()
        .build();
  }
}
