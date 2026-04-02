# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2026.0877.1");
  script_cve_id("CVE-2025-66614", "CVE-2026-24733", "CVE-2026-24734");
  script_tag(name:"creation_date", value:"2026-03-16 04:54:03 +0000 (Mon, 16 Mar 2026)");
  script_version("2026-03-16T06:13:25+0000");
  script_tag(name:"last_modification", value:"2026-03-16 06:13:25 +0000 (Mon, 16 Mar 2026)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-03-11 15:19:57 +0000 (Wed, 11 Mar 2026)");

  script_name("openSUSE Security Advisory (SUSE-SU-2026:0877-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:0877-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20260877-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253460");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258371");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258385");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258387");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-March/024680.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tomcat11' package(s) announced via the SUSE-SU-2026:0877-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for tomcat11 fixes the following issues:

Update to Tomcat 11.0.18:

- CVE-2025-66614: client certificate verification bypass due to virtual host mapping (bsc#1258371).
- CVE-2026-24733: improper input validation on HTTP/0.9 requests (bsc#1258385).
- CVE-2026-24734: certificate revocation bypass due to incomplete OCSP verification checks (bsc#1258387).

Changelog:

 * Catalina
 + Fix: 69932: Fix request end access log pattern regression, which would log
 the start time of the request instead. (remm)
 + Fix: 69623: Additional fix for the long standing regression that meant
 that calls to ClassLoader.getResource().getContent() failed when made from
 within a web application with resource caching enabled if the target
 resource was packaged in a JAR file. (markt)
 + Fix: Pull request #923: Avoid adding multiple CSRF tokens to a URL in the
 CsrfPreventionFilter. (schultz)
 + Fix: 69918: Ensure request parameters are correctly parsed for HTTP/2
 requests when the content-length header is not set. (dsoumis)
 + Update: Enable minimum and recommended Tomcat Native versions to be set
 separately for Tomcat Native 1.x and 2.x. Update the minimum and
 recommended versions for Tomcat Native 1.x to 1.3.4. Update the minimum
 and recommended versions for Tomcat Native 2.x to 2.0.12. (markt)
 + Add: Add a new ssoReauthenticationMode to the Tomcat provided
 Authenticators that provides a per Authenticator override of the SSO Valve
 requireReauthentication attribute. (markt)
 + Fix: Ensure URL encoding errors in the Rewrite Valve trigger an exception
 rather than silently using a replacement character. (markt)
 + Fix: 69871: Increase log level to INFO for missing configuration for the
 rewrite valve. (remm)
 + Fix: Add log warnings for additional Host appBase suspicious values.
 (remm)
 + Fix: Remove hard dependency on tomcat-jni.jar for catalina.jar.
 org.apache.catalina.Connector no longer requires
 org.apache.tomcat.jni.AprStatus to be present. (markt)
 + Add: Add the ability to use a custom function to generate the client
 identifier in the CrawlerSessionManagerValve. This is only available
 programmatically. Pull request #902 by Brian Matzon. (markt)
 + Fix: Change the SSO reauthentication behaviour for SPNEGO authentication
 so that a normal SPNEGO authentication is performed if the SSL Valve is
 configured with reauthentication enabled. This is so that the delegated
 credentials will be available to the web application. (markt)
 + Fix: When generating the class path in the Loader, re-order the check on
 individual class path components to avoid a potential
 NullPointerException. Identified by Coverity Scan. (markt)
 + Fix: Fix SSL socket factory configuration in the JNDI realm. Based on pull
 request #915 by Joshua Rogers. (remm)
 + Update: Add an attribute, digestInRfc3112Order, to
 MessageDigestCredentialHandler to control the order in which the
 credential and salt ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'tomcat11' package(s) on openSUSE Leap 15.6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"tomcat11", rpm:"tomcat11~11.0.18~150600.13.15.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat11-admin-webapps", rpm:"tomcat11-admin-webapps~11.0.18~150600.13.15.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat11-doc", rpm:"tomcat11-doc~11.0.18~150600.13.15.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat11-docs-webapp", rpm:"tomcat11-docs-webapp~11.0.18~150600.13.15.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat11-el-6_0-api", rpm:"tomcat11-el-6_0-api~11.0.18~150600.13.15.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat11-embed", rpm:"tomcat11-embed~11.0.18~150600.13.15.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat11-jsp-4_0-api", rpm:"tomcat11-jsp-4_0-api~11.0.18~150600.13.15.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat11-jsvc", rpm:"tomcat11-jsvc~11.0.18~150600.13.15.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat11-lib", rpm:"tomcat11-lib~11.0.18~150600.13.15.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat11-servlet-6_1-api", rpm:"tomcat11-servlet-6_1-api~11.0.18~150600.13.15.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat11-webapps", rpm:"tomcat11-webapps~11.0.18~150600.13.15.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
