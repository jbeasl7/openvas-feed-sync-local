# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856752");
  script_cve_id("CVE-2024-52316");
  script_tag(name:"creation_date", value:"2024-11-29 05:00:45 +0000 (Fri, 29 Nov 2024)");
  script_version("2025-09-11T05:38:37+0000");
  script_tag(name:"last_modification", value:"2025-09-11 05:38:37 +0000 (Thu, 11 Sep 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:4105-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5|openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:4105-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20244105-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233434");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-November/019867.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tomcat10' package(s) announced via the SUSE-SU-2024:4105-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for tomcat10 fixes the following issues:

- Update to Tomcat 10.1.33
 * Fixed CVEs:
 + CVE-2024-52316: If the Jakarta Authentication fails with an exception,
 set a 500 status (bsc#1233434)
 * Catalina
 + Add: Add support for the new Servlet API method HttpServletResponse.sendEarlyHints(). (markt)
 + Add: 55470: Add debug logging that reports the class path when a
 ClassNotFoundException occurs in the digester or the web application class loader.
 Based on a patch by Ralf Hauser. (markt)
 + Update: 69374: Properly separate between table header and body in
 DefaultServlet's listing. (michaelo)
 + Update: 69373: Make DefaultServlet's HTML listing file last modified
 rendering better (flexible). (michaelo)
 + Update: Improve HTML output of DefaultServlet. (michaelo)
 + Code: Refactor RateLimitFilter to use FilterBase as the base class.
 The primary advantage is less code to process init-param values. (markt)
 + Update: 69370: DefaultServlet's HTML listing uses incorrect labels.
 (michaelo)
 + Fix: Avoid NPE in CrawlerSessionManagerValve for partially mapped requests. (remm)
 + Fix: Add missing WebDAV Lock-Token header in the response when locking
 a folder. (remm)
 + Fix: Invalid WebDAV lock requests should be rejected with 400. (remm)
 + Fix: Fix regression in WebDAV when attempting to unlock a collection. (remm)
 + Fix: Verify that destination is not locked for a WebDAV copy operation. (remm)
 + Fix: Send 415 response to WebDAV MKCOL operations that include a request
 body since this is optional and unsupported. (remm)
 + Fix: Enforce DAV: namespace on WebDAV XML elements. (remm)
 + Fix: Do not allow a new WebDAV lock on a child resource if a parent
 collection is locked (RFC 4918 section 6.1). (remm)
 + Fix: WebDAV DELETE should remove any existing lock on successfully
 deleted resources. (remm)
 + Update: Remove WebDAV lock null support in accordance with RFC 4918
 section 7.3 and annex D. Instead, a lock on a non-existing resource will
 create an empty file locked with a regular lock. (remm)
 + Update: Rewrite implementation of WebDAV shared locks to comply with
 RFC 4918. (remm)
 + Update: Implement WebDAV If header using code from the Apache Jackrabbit
 project. (remm)
 + Add: Add PropertyStore interface in the WebDAV Servlet, to allow
 implementation of dead properties storage. The store used can be configured
 using the propertyStore init parameter of the WebDAV servlet by specifying
 the class name of the store. A simple non-persistent implementation is
 used if no custom store is configured. (remm)
 + Update: Implement WebDAV PROPPATCH method using the newly added
 PropertyStore, and update PROPFIND to support it. (remm)
 + Fix: Cache not found results when searching for web application class
 loader resources. This addresses performance problems caused by components
 such as java.sql.DriverManager, which in some circumstances will search
 for the ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'tomcat10' package(s) on openSUSE Leap 15.5, openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"tomcat10", rpm:"tomcat10~10.1.33~150200.5.28.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat10-admin-webapps", rpm:"tomcat10-admin-webapps~10.1.33~150200.5.28.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat10-docs-webapp", rpm:"tomcat10-docs-webapp~10.1.33~150200.5.28.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat10-el-5_0-api", rpm:"tomcat10-el-5_0-api~10.1.33~150200.5.28.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat10-embed", rpm:"tomcat10-embed~10.1.33~150200.5.28.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat10-jsp-3_1-api", rpm:"tomcat10-jsp-3_1-api~10.1.33~150200.5.28.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat10-jsvc", rpm:"tomcat10-jsvc~10.1.33~150200.5.28.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat10-lib", rpm:"tomcat10-lib~10.1.33~150200.5.28.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat10-servlet-6_0-api", rpm:"tomcat10-servlet-6_0-api~10.1.33~150200.5.28.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat10-webapps", rpm:"tomcat10-webapps~10.1.33~150200.5.28.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"tomcat10", rpm:"tomcat10~10.1.33~150200.5.28.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat10-admin-webapps", rpm:"tomcat10-admin-webapps~10.1.33~150200.5.28.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat10-doc", rpm:"tomcat10-doc~10.1.33~150200.5.28.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat10-docs-webapp", rpm:"tomcat10-docs-webapp~10.1.33~150200.5.28.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat10-el-5_0-api", rpm:"tomcat10-el-5_0-api~10.1.33~150200.5.28.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat10-embed", rpm:"tomcat10-embed~10.1.33~150200.5.28.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat10-jsp-3_1-api", rpm:"tomcat10-jsp-3_1-api~10.1.33~150200.5.28.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat10-jsvc", rpm:"tomcat10-jsvc~10.1.33~150200.5.28.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat10-lib", rpm:"tomcat10-lib~10.1.33~150200.5.28.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat10-servlet-6_0-api", rpm:"tomcat10-servlet-6_0-api~10.1.33~150200.5.28.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat10-webapps", rpm:"tomcat10-webapps~10.1.33~150200.5.28.1", rls:"openSUSELeap15.6"))) {
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
