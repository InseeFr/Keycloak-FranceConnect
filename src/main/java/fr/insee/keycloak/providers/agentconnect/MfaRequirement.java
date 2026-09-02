package fr.insee.keycloak.providers.agentconnect;

enum MfaRequirement {
  DISABLED,
  OPTIONAL,
  REQUIRED;

  static final String MFA_MODE_PROPERTY_NAME = "mfa_mode";

  @Override
  public String toString() {
    return name().toLowerCase();
  }

  static MfaRequirement getOrDefault(String mfaRequirementName, MfaRequirement defaultMfaRequirement) {
    for (var mfaRequirement : MfaRequirement.values()) {
      if (mfaRequirement.name().equalsIgnoreCase(mfaRequirementName)) {
        return mfaRequirement;
      }
    }

    return defaultMfaRequirement;
  }
}
