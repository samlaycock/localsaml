/*
 * Runs the SAML Conformance Test Kit's tests and reports JUnit's real result for each one.
 *
 * The kit's own runner (samlconf) prints SUCCESSFUL for any test that didn't record a
 * SAMLComplianceException, so a test that dies with any other exception (a parse error, a
 * NullPointerException, an unexpected HTTP status) is reported as passing. This runner sets the
 * same system properties as samlconf, runs the same test classes, and prints each test's actual
 * JUnit status with the exception message, then writes the kit's section report as usual.
 *
 * Usage: java -cp "/samlconf/lib/*:runner.jar" org.localsaml.ctk.Runner <implementation dir> [--lenient]
 */
package org.localsaml.ctk;

import static org.junit.platform.engine.discovery.DiscoverySelectors.selectClass;

import java.util.ArrayList;
import java.util.List;
import org.junit.platform.engine.TestExecutionResult;
import org.junit.platform.launcher.Launcher;
import org.junit.platform.launcher.LauncherDiscoveryRequest;
import org.junit.platform.launcher.TestExecutionListener;
import org.junit.platform.launcher.TestIdentifier;
import org.junit.platform.launcher.core.LauncherDiscoveryRequestBuilder;
import org.junit.platform.launcher.core.LauncherFactory;

public class Runner {
  private static final String[] TESTS = {
    "org.codice.compliance.web.sso.PostSSOTest",
    "org.codice.compliance.web.sso.error.PostSSOErrorTest",
    "org.codice.compliance.web.slo.PostSLOTest",
    "org.codice.compliance.web.slo.error.PostSLOErrorTest",
    "org.codice.compliance.web.sso.RedirectSSOTest",
    "org.codice.compliance.web.sso.error.RedirectSSOErrorTest",
    "org.codice.compliance.web.slo.RedirectSLOTest",
    "org.codice.compliance.web.slo.error.RedirectSLOErrorTest",
  };

  public static void main(String[] args) throws Exception {
    String home = System.getProperty("app.home", "/samlconf");
    boolean lenient = args.length > 1 && args[1].equals("--lenient");
    System.setProperty("implementation.path", args.length > 0 ? args[0] : "/impl");
    System.setProperty("user.login", "admin:admin");
    System.setProperty("test.sp.metadata", home + "/conf/samlconf-sp-metadata.xml");
    System.setProperty("lenient.error.verification", Boolean.toString(lenient));
    System.setProperty("run.ddf.profile", "false");
    System.setProperty("quiet.mode", "false");

    List<org.junit.platform.engine.DiscoverySelector> selectors = new ArrayList<>();
    for (String t : TESTS) selectors.add(selectClass(Class.forName(t)));
    LauncherDiscoveryRequest request = LauncherDiscoveryRequestBuilder.request().selectors(selectors).build();

    final int[] counts = new int[3]; // passed, failed, aborted
    TestExecutionListener listener = new TestExecutionListener() {
      @Override
      public void executionFinished(TestIdentifier id, TestExecutionResult result) {
        if (!id.isTest()) {
          if (result.getStatus() != TestExecutionResult.Status.SUCCESSFUL) {
            System.out.println("CONTAINER " + result.getStatus() + ": " + id.getDisplayName() + " " + why(result));
          }
          return;
        }
        String status = result.getStatus().toString();
        int slot = result.getStatus() == TestExecutionResult.Status.SUCCESSFUL ? 0
            : result.getStatus() == TestExecutionResult.Status.FAILED ? 1 : 2;
        counts[slot]++;
        System.out.println("RESULT " + status + " | " + id.getDisplayName() + (slot == 0 ? "" : " | " + why(result)));
      }

      @Override
      public void executionSkipped(TestIdentifier id, String reason) {
        System.out.println("RESULT SKIPPED | " + id.getDisplayName() + " | " + reason);
      }
    };
    Launcher launcher = LauncherFactory.create();
    launcher.execute(request, listener);
    org.codice.compliance.report.Report.INSTANCE.writeReport();
    System.out.println("SUMMARY passed=" + counts[0] + " failed=" + counts[1] + " aborted=" + counts[2]);
    System.exit(counts[1] + counts[2] > 0 ? 1 : 0);
  }

  private static String why(TestExecutionResult result) {
    return result.getThrowable().map(t -> {
      String msg = t.getClass().getName() + ": " + String.valueOf(t.getMessage()).replace('\n', ' ');
      // Where in the kit it failed: the innermost few kit frames.
      StringBuilder where = new StringBuilder();
      int shown = 0;
      for (StackTraceElement e : t.getStackTrace()) {
        if (e.getClassName().startsWith("org.codice") && shown++ < 3) where.append(" at ").append(e);
      }
      return msg + " |" + where;
    }).orElse("");
  }
}
