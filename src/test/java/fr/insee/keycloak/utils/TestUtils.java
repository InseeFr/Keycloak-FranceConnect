package fr.insee.keycloak.utils;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.net.URI;
import java.util.Arrays;
import java.util.Map;
import java.util.stream.Collectors;

public final class TestUtils {

  private TestUtils() {
  }

  public static Map<String, String> uriQueryStringToMap(URI uri) {
    return Arrays.stream(uri.getQuery().split("&"))
        .map(param -> param.split("="))
        .collect(Collectors.toMap(part -> part[0], part -> part[1]));
  }

  public static String mapToJsonFormat(Map<String, String> mapObject) {
    try {
      return new ObjectMapper().writeValueAsString(mapObject);
    } catch (JsonProcessingException e) {
      throw new IllegalStateException(e);
    }
  }
}
