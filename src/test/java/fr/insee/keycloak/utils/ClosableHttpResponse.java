package fr.insee.keycloak.utils;

import org.apache.http.*;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.entity.BasicHttpEntity;
import org.apache.http.params.HttpParams;
import org.apache.http.protocol.BasicHttpContext;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.Map;

import static org.apache.http.impl.DefaultHttpResponseFactory.INSTANCE;

/**
 * Copy of org.apache.http.impl.execchain.HttpResponseProxy class but with public visibility :)
 * Used by CloseableHttpClient
 */
public final class ClosableHttpResponse implements CloseableHttpResponse {

  private final HttpResponse original;

  private ClosableHttpResponse(HttpResponse original) {
    this.original = original;
  }

  public static ClosableHttpResponse from(Map<String, String> headers, String body) {
    var httpEntity = new BasicHttpEntity();
    httpEntity.setContent(new ByteArrayInputStream(body.getBytes(StandardCharsets.UTF_8)));

    var originalResponse = INSTANCE.newHttpResponse(
        new ProtocolVersion("HTTP", 1, 1),
        200, new BasicHttpContext()
    );
    headers.forEach(originalResponse::setHeader);
    originalResponse.setEntity(httpEntity);

    return new ClosableHttpResponse(originalResponse);
  }

  public void close() {}

  public StatusLine getStatusLine() {
    return this.original.getStatusLine();
  }

  public void setStatusLine(StatusLine statusline) {
    this.original.setStatusLine(statusline);
  }

  public void setStatusLine(ProtocolVersion ver, int code) {
    this.original.setStatusLine(ver, code);
  }

  public void setStatusLine(ProtocolVersion ver, int code, String reason) {
    this.original.setStatusLine(ver, code, reason);
  }

  public void setStatusCode(int code) throws IllegalStateException {
    this.original.setStatusCode(code);
  }

  public void setReasonPhrase(String reason) throws IllegalStateException {
    this.original.setReasonPhrase(reason);
  }

  public HttpEntity getEntity() {
    return this.original.getEntity();
  }

  public void setEntity(HttpEntity entity) {
    this.original.setEntity(entity);
  }

  public Locale getLocale() {
    return this.original.getLocale();
  }

  public void setLocale(Locale loc) {
    this.original.setLocale(loc);
  }

  public ProtocolVersion getProtocolVersion() {
    return this.original.getProtocolVersion();
  }

  public boolean containsHeader(String name) {
    return this.original.containsHeader(name);
  }

  public Header[] getHeaders(String name) {
    return this.original.getHeaders(name);
  }

  public Header getFirstHeader(String name) {
    return this.original.getFirstHeader(name);
  }

  public Header getLastHeader(String name) {
    return this.original.getLastHeader(name);
  }

  public Header[] getAllHeaders() {
    return this.original.getAllHeaders();
  }

  public void addHeader(Header header) {
    this.original.addHeader(header);
  }

  public void addHeader(String name, String value) {
    this.original.addHeader(name, value);
  }

  public void setHeader(Header header) {
    this.original.setHeader(header);
  }

  public void setHeader(String name, String value) {
    this.original.setHeader(name, value);
  }

  public void setHeaders(Header[] headers) {
    this.original.setHeaders(headers);
  }

  public void removeHeader(Header header) {
    this.original.removeHeader(header);
  }

  public void removeHeaders(String name) {
    this.original.removeHeaders(name);
  }

  public HeaderIterator headerIterator() {
    return this.original.headerIterator();
  }

  public HeaderIterator headerIterator(String name) {
    return this.original.headerIterator(name);
  }

  public HttpParams getParams() {
    return this.original.getParams();
  }

  public void setParams(HttpParams params) {
    this.original.setParams(params);
  }

  public String toString() {
    StringBuilder sb = new StringBuilder("HttpResponseProxy{");
    sb.append(this.original);
    sb.append('}');
    return sb.toString();
  }
}
