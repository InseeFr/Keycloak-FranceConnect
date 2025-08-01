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
    String attributeValue = this.attributes.get(attributeName).get(0);
    if (attributeValue == null) {
      throw new RuntimeException(String.format("Missing attribute value for claim '%s' / attribute '%s'", claimName, attributeName));
    }
    return entry(attributeName, attributeValue);
  }

  public Map<String, String> toMap() {
    return Map.ofEntries(
        resolve(CLAIM_GIVEN_NAME),
        resolve(CLAIM_FAMILY_NAME),
        resolve(CLAIM_GENDER),
        resolve(CLAIM_BIRTHDATE),
        resolve(CLAIM_BIRTHPLACE),
        resolve(CLAIM_BIRTHCOUNTRY)
    );
  }

  @Override
  public String toString() {
    return this.toMap().toString();
  }
}
