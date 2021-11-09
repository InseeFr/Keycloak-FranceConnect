package fr.insee.keycloak.providers.common;

public enum EidasLevel {
    EIDAS1,
    EIDAS2,
    EIDAS3;

    public static final String EIDAS_LEVEL_PROPERTY_NAME = "eidas_values";

    @Override
    public String toString() {
        return name().toLowerCase();
    }

    public static EidasLevel getOrDefault(String eidasLevelName, EidasLevel defaultEidasLevel) {
        for (var eidasLevel : EidasLevel.values()) {
            if (eidasLevel.name().equalsIgnoreCase(eidasLevelName)) {
                return eidasLevel;
            }
        }

        return defaultEidasLevel;
    }
}
