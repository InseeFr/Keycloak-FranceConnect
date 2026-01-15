package fr.insee.keycloak.providers.franceconnect;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static java.util.Map.entry;

public class IdentitePivot {
  // https://docs.partenaires.franceconnect.gouv.fr/fi/general/donnees-utilisateur/#l-identite-pivot
  static final public String CLAIM_GIVEN_NAME = "given_name";
  static final public String CLAIM_FAMILY_NAME = "family_name";
  static final public String CLAIM_GENDER = "gender";
  static final public String CLAIM_BIRTHDATE = "birthdate";
  static final public String CLAIM_BIRTHPLACE = "birthplace";
  static final public String CLAIM_BIRTHCOUNTRY = "birthcountry";

  static final public List<String> DEFAULT_CLAIMS = List.of(CLAIM_GIVEN_NAME, CLAIM_FAMILY_NAME, CLAIM_GENDER, CLAIM_BIRTHDATE, CLAIM_BIRTHPLACE, CLAIM_BIRTHCOUNTRY);

  static final String ACCOUNT_LINKING_CLAIMS_PROPERTY_NAME = "fc_account_linking_claims";

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

  public  Map<String, String> toMap() {
    return toMap(this.attributeMapping.keySet());
  }

  public Map<String, String> toMap(Set<String> claims) {
    Map<String, String> attributes = new java.util.HashMap<>();

    for (String claim : claims) {
      if(CLAIM_BIRTHPLACE.equals(claim)) {
        if (!resolve(CLAIM_BIRTHCOUNTRY).getValue().equals(INSEE_CODE_FRANCE)) {
          // add "birthplace" attribute only for users born in France
          // see description for the "birthplace" claim: https://docs.partenaires.franceconnect.gouv.fr/fi/general/donnees-utilisateur/#l-identite-pivot
          continue;
        }
      }

      Map.Entry<String, String> attr = resolve(claim);
      attributes.put(attr.getKey(), attr.getValue());
    }

    return attributes;
  }

  @Override
  public String toString() {
    return this.toMap().toString();
  }
}
