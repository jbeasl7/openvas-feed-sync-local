# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.1126.1");
  script_cve_id("CVE-2024-56337", "CVE-2025-24813");
  script_tag(name:"creation_date", value:"2025-04-07 04:06:30 +0000 (Mon, 07 Apr 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-03-18 14:15:43 +0000 (Tue, 18 Mar 2025)");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:1126-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:1126-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20251126-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1239302");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1239676");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-April/038899.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tomcat' package(s) announced via the SUSE-SU-2025:1126-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for tomcat fixes the following issues:

- CVE-2025-24813: Fixed potential RCE and/or information disclosure/corruption with partial PUT (bsc#1239302)

- Update to Tomcat 9.0.102
 * Fixes:
 + launch with java 17 (bsc#1239676)
 * Catalina
 + Fix: Weak etags in the If-Range header should not match as strong etags
 are required. (remm)
 + Fix: When looking up class loader resources by resource name, the resource
 name should not start with '/'. If the resource name does start with '/',
 Tomcat is lenient and looks it up as if the '/' was not present. When the
 web application class loader was configured with external repositories and
 names starting with '/' were used for lookups, it was possible that cached
 'not found' results could effectively hide lookup results using the
 correct resource name. (markt)
 + Fix: Enable the JNDIRealm to validate credentials provided to
 HttpServletRequest.login(String username, String password) when the realm
 is configured to use GSSAPI authentication. (markt)
 + Fix: Fix a bug in the JRE compatibility detection that incorrectly
 identified Java 19 and Java 20 as supporting Java 21 features. (markt)
 + Fix: Improve the checks for exposure to and protection against
 CVE-2024-56337 so that reflection is not used unless required. The checks
 for whether the file system is case sensitive or not have been removed.
 (markt)
 + Fix: Avoid scenarios where temporary files used for partial PUT would not
 be deleted. (remm)
 + Fix: 69602: Fix regression in releases from 12-2024 that were too strict
 and rejected weak etags in the If-Range header. (remm)
 + Fix: 69576: Avoid possible failure initializing JreCompat due to uncaught
 exception introduced for the check for CVE-2024-56337. (remm)
 * Cluster
 + Add: 69598: Add detection of service account token changes to the
 KubernetesMembershipProvider implementation and reload the token if it
 changes. Based on a patch by Miroslav Jezbera. (markt)
 * Coyote
 + Fix: 69575: Avoid using compression if a response is already compressed
 using compress, deflate or zstd. (remm)
 + Update: Use Transfer-Encoding for compression rather than Content-Encoding
 if the client submits a TE header containing gzip. (remm)
 + Fix: Fix a race condition in the handling of HTTP/2 stream reset that
 could cause unexpected 500 responses. (markt)
 * Other
 + Add: Add makensis as an option for building the Installer for Windows on
 non-Windows platforms. (rjung/markt)
 + Update: Update Byte Buddy to 1.17.1. (markt)
 + Update: Update Checkstyle to 10.21.3. (markt)
 + Update: Update SpotBugs to 4.9.1. (markt)
 + Update: Update JSign to 7.1. (markt)
 + Add: Improvements to French translations. (remm)
 + Add: Improvements to Japanese translations by tak7iji. (markt)
 + Add: Add org.apache.juli.JsonFormatter to format log as one line JSON
 documents. (remm)

- Update to Tomcat 9.0.99
 * Catalina
 + Update: Add tableName ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'tomcat' package(s) on openSUSE Leap 15.6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

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

  if(!isnull(res = isrpmvuln(pkg:"tomcat", rpm:"tomcat~9.0.102~150200.78.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-admin-webapps", rpm:"tomcat-admin-webapps~9.0.102~150200.78.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-docs-webapp", rpm:"tomcat-docs-webapp~9.0.102~150200.78.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-el-3_0-api", rpm:"tomcat-el-3_0-api~9.0.102~150200.78.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-embed", rpm:"tomcat-embed~9.0.102~150200.78.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-javadoc", rpm:"tomcat-javadoc~9.0.102~150200.78.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-jsp-2_3-api", rpm:"tomcat-jsp-2_3-api~9.0.102~150200.78.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-jsvc", rpm:"tomcat-jsvc~9.0.102~150200.78.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-lib", rpm:"tomcat-lib~9.0.102~150200.78.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-servlet-4_0-api", rpm:"tomcat-servlet-4_0-api~9.0.102~150200.78.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-webapps", rpm:"tomcat-webapps~9.0.102~150200.78.1", rls:"openSUSELeap15.6"))) {
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
