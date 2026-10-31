/*
 * A SAML Conformance Test Kit plugin for localsaml. The kit sends an AuthnRequest; localsaml
 * answers with its login page (or, with --auto-login, straight away with the Response). This
 * plugin submits the login form unchanged, which signs in with the template's default identity,
 * and hands the kit the page that posts the SAML Response.
 */
package org.codice.compliance.saml.plugin.localsaml;

import io.restassured.RestAssured;
import io.restassured.response.Response;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.codice.compliance.saml.plugin.IdpSSOResponder;
import org.codice.compliance.utils.GlobalSessionKt;

public class LocalsamlIdpSSOResponder implements IdpSSOResponder {
  private static final Pattern FORM_ACTION =
      Pattern.compile("<form[^>]*id=\"lo-form\"[^>]*action=\"([^\"]*)\"|<form[^>]*action=\"([^\"]*)\"[^>]*id=\"lo-form\"");
  private static final Pattern REQ = Pattern.compile("name=\"req\" value=\"([^\"]*)\"");

  /** Where localsaml is, as the kit reaches it (relative form actions are resolved against it). */
  private static String base() {
    String base = System.getenv("LOCALSAML_BASE_URL");
    if (base == null || base.isEmpty()) base = System.getProperty("localsaml.base", "http://host.docker.internal:9412");
    return base.replaceAll("/+$", "");
  }

  @Override
  public Response getResponseForRedirectRequest(Response originalResponse) {
    return signIn(originalResponse);
  }

  @Override
  public Response getResponseForPostRequest(Response originalResponse) {
    return signIn(originalResponse);
  }

  /**
   * Requests go through the kit's global HTTP session, so localsaml's session cookie (set when a
   * login completes) is sent with later logins and logouts in the same test, as a browser would.
   */
  private static io.restassured.specification.RequestSpecification session() {
    return GlobalSessionKt.usingTheGlobalHttpSession(
        RestAssured.given().urlEncodingEnabled(false).redirects().follow(false));
  }

  private Response signIn(Response response) {
    // Follow redirects (a template alias, or anything else that redirects first).
    for (int i = 0; i < 5 && response.getStatusCode() / 100 == 3; i++) {
      response = session().when().get(response.getHeader("Location"));
    }
    String body = response.getBody().asString();
    // Already the Response (auto-login, a passive request, or an error status).
    if (body.contains("name=\"SAMLResponse\"")) return response;
    Matcher req = REQ.matcher(body);
    Matcher action = FORM_ACTION.matcher(body);
    if (!req.find() || !action.find()) return response; // an error page: let the kit judge it
    String target = action.group(1) != null ? action.group(1) : action.group(2);
    if (target.startsWith("/")) {
      java.net.URI b = java.net.URI.create(base());
      target = b.getScheme() + "://" + b.getRawAuthority() + target;
    }
    return session()
        .contentType("application/x-www-form-urlencoded")
        .body("req=" + req.group(1) + "&action=approve&preset=&identity=")
        .when().post(target);
  }
}
