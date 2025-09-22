# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.1024.1");
  script_cve_id("CVE-2024-56337", "CVE-2025-24813");
  script_tag(name:"creation_date", value:"2025-03-28 04:07:29 +0000 (Fri, 28 Mar 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-03-18 14:15:43 +0000 (Tue, 18 Mar 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:1024-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:1024-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20251024-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1239302");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1239676");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-March/020602.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tomcat10' package(s) announced via the SUSE-SU-2025:1024-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for tomcat10 fixes the following issues:

- CVE-2025-24813: Fixed potential RCE and/or information disclosure/corruption with
 partial PUT (bsc#1239302)

Other fixes:

- Update to Tomcat 10.1.39
 * Fixes:
 + launch with java 17 (bsc#1239676)
 * Catalina
 + Fix: 69602: Fix regression in releases from 12-2024 that were too strict
 and rejected weak etags in the If-Range header with a 400 response.
 Instead will consider it as a failed match since strong etags are required
 for If-Range. (remm)
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
 + Add: Add support for logging the connection ID (as returned by
 ServletRequest.getServletConnection().getConnectionId()) with the
 AccessLogValve and ExtendedAccessLogValve. Based on pull request #814 by
 Dmole. (markt)
 + Fix: Avoid scenarios where temporary files used for partial PUT would not
 be deleted. (remm)
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
 + Add: ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'tomcat10' package(s) on SUSE Linux Enterprise Server 15-SP5, SUSE Linux Enterprise Server for SAP Applications 15-SP5.");

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

if(release == "SLES15.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"tomcat10", rpm:"tomcat10~10.1.39~150200.5.36.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat10-admin-webapps", rpm:"tomcat10-admin-webapps~10.1.39~150200.5.36.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat10-el-5_0-api", rpm:"tomcat10-el-5_0-api~10.1.39~150200.5.36.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat10-jsp-3_1-api", rpm:"tomcat10-jsp-3_1-api~10.1.39~150200.5.36.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat10-lib", rpm:"tomcat10-lib~10.1.39~150200.5.36.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat10-servlet-6_0-api", rpm:"tomcat10-servlet-6_0-api~10.1.39~150200.5.36.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat10-webapps", rpm:"tomcat10-webapps~10.1.39~150200.5.36.1", rls:"SLES15.0SP5"))) {
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
