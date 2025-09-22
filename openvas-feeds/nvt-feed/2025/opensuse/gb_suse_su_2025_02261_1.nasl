# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.02261.1");
  script_cve_id("CVE-2025-46701", "CVE-2025-48988", "CVE-2025-49125");
  script_tag(name:"creation_date", value:"2025-07-11 04:18:18 +0000 (Fri, 11 Jul 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:02261-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:02261-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202502261-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242722");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243815");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244649");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244656");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-July/040657.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tomcat10' package(s) announced via the SUSE-SU-2025:02261-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for tomcat10 fixes the following issues:

- Fixed refactor CGI servlet to access resources via WebResources (bsc#1243815).
- Fixed limits the total number of parts in a multi-part request and
 limits the size of the headers provided with each part (bsc#1244656).
- Fixed expand checks for webAppMount (bsc#1244649).
- Hardening permissions (bsc#1242722)

Update to Tomcat 10.1.42:

 * Fixed CVEs:

 + CVE-2025-46701: refactor CGI servlet to access resources via
 WebResources (bsc#1243815)
 + CVE-2025-48988: limits the total number of parts in a
 multi-part request and limits the size of
 the headers provided with each part (bsc#1244656)
 + CVE-2025-49125: Expand checks for webAppMount (bsc#1244649)

 * Catalina:

 + Add: Support for the java:module namespace which mirrors the
 java:comp namespace.
 + Add: Support parsing of multiple path parameters separated by , in a
 single URL segment. Based on pull request #860 by Chenjp.
 + Add: Support for limiting the number of parameters in HTTP requests
 through the new ParameterLimitValve. The valve allows configurable
 URL-specific limits on the number of parameters.
 + Fix: 69699: Encode redirect URL used by the rewrite valve with the
 session id if appropriate, and handle cross context with different
 session configuration when using rewrite.
 + Add: #863: Support for comments at the end of lines in text rewrite
 map files to align behaviour with Apache httpd. Pull request
 provided by Chenjp.
 + Fix: 69706: Saved request serialization issue in FORM introduced
 when allowing infinite session timeouts.
 + Fix: Expand the path checks for Pre-Resources and Post-Resources
 mounted at a path within the web application.
 + Fix: Use of SSS in SimpleDateFormat pattern for AccessLogValve.
 + Fix: Process possible path parameters rewrite production in the
 rewrite valve.
 + Fix: 69588: Enable allowLinking to be set on PreResources,
 JarResources and PostResources. If not set explicitly, the setting
 will be inherited from the Resources.
 + Add: 69633: Support for Filters using context root mappings.
 + Fix: 69643: Optimize directory listing for large amount of files.
 Patch submitted by Loic de l'Eprevier.
 + Fix: #843: Off by one validation logic for partial PUT ranges and
 associated test case. Submitted by Chenjp.
 + Refactor: Replace the unused buffer in
 org.apache.catalina.connector.InputBuffer with a static, zero
 length buffer.
 + Refactor: GCI servlet to access resources via the WebResource API.
 + Fix: 69662: Report name in exception message when a naming lookup
 failure occurs. Based on code submitted by Donald Smith.
 + Fix: Ensure that the FORM authentication attribute
 authenticationSessionTimeout works correctly when sessions have an
 infinite timeout when authentication starts.
 + Add: Provide a content type based on file extension when web
 application resources are accessed via a URL.
 * Coyote
 + Refactor: ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'tomcat10' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"tomcat10", rpm:"tomcat10~10.1.42~150200.5.45.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat10-admin-webapps", rpm:"tomcat10-admin-webapps~10.1.42~150200.5.45.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat10-doc", rpm:"tomcat10-doc~10.1.42~150200.5.45.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat10-docs-webapp", rpm:"tomcat10-docs-webapp~10.1.42~150200.5.45.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat10-el-5_0-api", rpm:"tomcat10-el-5_0-api~10.1.42~150200.5.45.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat10-embed", rpm:"tomcat10-embed~10.1.42~150200.5.45.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat10-jsp-3_1-api", rpm:"tomcat10-jsp-3_1-api~10.1.42~150200.5.45.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat10-jsvc", rpm:"tomcat10-jsvc~10.1.42~150200.5.45.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat10-lib", rpm:"tomcat10-lib~10.1.42~150200.5.45.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat10-servlet-6_0-api", rpm:"tomcat10-servlet-6_0-api~10.1.42~150200.5.45.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat10-webapps", rpm:"tomcat10-webapps~10.1.42~150200.5.45.1", rls:"openSUSELeap15.6"))) {
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
