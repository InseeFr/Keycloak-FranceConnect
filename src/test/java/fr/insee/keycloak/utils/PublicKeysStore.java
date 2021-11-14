package fr.insee.keycloak.utils;

import com.fasterxml.jackson.annotation.JsonRawValue;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public final class PublicKeysStore {

  private final List<String> keys = new ArrayList<>();

  public PublicKeysStore add(String key) {
    keys.add(key);
    return this;
  }

  @JsonRawValue
  public List<String> getKeys() {
    return keys;
  }

  public String toJsonFormat() {
    try {
      return new ObjectMapper().writeValueAsString(this);
    } catch (JsonProcessingException e) {
      throw new IllegalStateException(e);
    }
  }

  public byte[] toJsonByteArray() {
    return toJsonFormat().getBytes(StandardCharsets.UTF_8);
  }
}
