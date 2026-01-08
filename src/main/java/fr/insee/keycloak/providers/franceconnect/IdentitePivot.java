package fr.insee.keycloak.providers.franceconnect;

import java.util.List;
import java.util.Map;

import static java.util.Map.entry;

public class IdentitePivot {
  // https://docs.partenaires.franceconnect.gouv.fr/fi/general/donnees-utilisateur/#l-identite-pivot
  static final public String CLAIM_GIVEN_NAME = "given_name";
  static final public String CLAIM_FAMILY_NAME = "family_name";
  static final public String CLAIM_GENDER = "gender";
  static final public String CLAIM_BIRTHDATE = "birthdate";
  static final public String CLAIM_BIRTHPLACE = "birthplace";
  static final public String CLAIM_BIRTHCOUNTRY = "birthcountry";

  // https://www.insee.fr/fr/metadonnees/geographie/pays/99100-france
  static final private String INSEE_CODE_FRANCE = "99100";

  private final Map<String, String> attributeMapping;
  private final Map<String, List<String>> attributes;

  public IdentitePivot(Map<String, String> attributeMapping, Map<String, List<String>> attributes) {
    this.attributeMapping = attributeMapping;
    this.attributes = attributes;
  }

  private Map.Entry<String, String> resolve(String claimName) {
    String attributeName = this.attributeMapping.get(claimName);
    if (attributeName == null) {
      throw new RuntimeException(String.format("Missing attribute mapper for claim '%s'", claimName));
    }
    List<String> attributeValues = this.attributes.get(attributeName);
    if (attributeValues == null) {
      throw new RuntimeException(String.format(" Missing attribute value for claim '%s' / attribute '%s'", claimName, attributeName));
    }
    return entry(attributeName, attributeValues.get(0));
  }

  public Map<String, String> toMap() {
    Map<String, String> attributes = new java.util.HashMap<>(Map.ofEntries(
        resolve(CLAIM_GIVEN_NAME),
        resolve(CLAIM_FAMILY_NAME),
        resolve(CLAIM_GENDER),
        resolve(CLAIM_BIRTHDATE),
        resolve(CLAIM_BIRTHCOUNTRY)
    ));

    // add "birthplace" attribute, only for users not born in France
    // see description for the "birthplace" claim: https://docs.partenaires.franceconnect.gouv.fr/fi/general/donnees-utilisateur/#l-identite-pivot
    if (INSEE_CODE_FRANCE.equals(resolve(CLAIM_BIRTHCOUNTRY).getValue())) {
      Map.Entry<String, String> birthPlace = resolve(CLAIM_BIRTHPLACE);
      attributes.put(birthPlace.getKey(), birthPlace.getValue());
    }

    return attributes;
  }

  @Override
  public String toString() {
    return this.toMap().toString();
  }
}
