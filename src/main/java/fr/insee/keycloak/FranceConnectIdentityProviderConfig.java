package fr.insee.keycloak;

import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.models.IdentityProviderModel;

public class FranceConnectIdentityProviderConfig extends OIDCIdentityProviderConfig {

   public FranceConnectIdentityProviderConfig(IdentityProviderModel identityProviderModel) {
      super(identityProviderModel);
   }
   
   public boolean isIgnoreAbsentStateParameterLogout() {
      return Boolean.valueOf(getConfig().get("ignoreAbsentStateParameterLogout"));
   }

   public void setIgnoreAbsentStateParameterLogout(boolean value){
      getConfig().put("ignoreAbsentStateParameterLogout", String.valueOf(value));
   }

   public String getAcrValues() {
      String acr_values = (String)getConfig().get("acr_values");
    
      return (acr_values == null) || (acr_values.isEmpty()) ? "eidas1" : acr_values;
   }
  
   public void setAcrValues(String acrValues) {
      getConfig().put("acr_values", acrValues);
   }
   
}
