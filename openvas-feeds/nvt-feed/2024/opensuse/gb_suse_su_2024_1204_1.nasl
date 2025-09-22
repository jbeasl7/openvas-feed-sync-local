# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856076");
  script_cve_id("CVE-2024-23672", "CVE-2024-24549");
  script_tag(name:"creation_date", value:"2024-04-17 01:01:25 +0000 (Wed, 17 Apr 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:1204-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1204-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20241204-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221385");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221386");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2024-April/034931.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tomcat10' package(s) announced via the SUSE-SU-2024:1204-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for tomcat10 fixes the following issues:

- CVE-2024-24549: Fixed denial of service during header validation for HTTP/2 stream (bsc#1221386)
- CVE-2024-23672: Fixed denial of service due to malicious WebSocket client keeping connection open (bsc#1221385)

Other fixes:
- Update to Tomcat 10.1.20
 * Catalina
 + Fix: Minor performance improvement for building filter chains.
 Based on ideas from #702 by Luke Miao. (remm)
 + Fix: Align error handling for Writer and OutputStream. Ensure
 use of either once the response has been recycled triggers a
 NullPointerException provided that discardFacades is configured with
 the default value of true. (markt)
 + Fix: 68692: The standard thread pool implementations that are
 configured using the Executor element now implement ExecutorService
 for better support NIO2. (remm)
 + Fix: 68495: When restoring a saved POST request after a
 successful FORM authentication, ensure that neither the URI, the
 query string nor the protocol are corrupted when restoring the
 request body. (markt)
 + Fix: After forwarding a request, attempt to unwrap the
 response in order to suspend it, instead of simply closing it if it
 was wrapped. Add a new suspendWrappedResponseAfterForward boolean
 attribute on Context to control the bahavior, defaulting to false.
 (remm)
 + Fix: 68721: Workaround a possible cause of duplicate class
 definitions when using ClassFileTransformers and the transformation
 of a class also triggers the loading of the same class. (markt)
 + Fix: The rewrite valve should not do a rewrite if the output
 is identical to the input. (remm)
 + Update: Add a new valveSkip (or VS) rule flag to the rewrite
 valve to allow skipping over the next valve in the Catalina pipeline.
 (remm)
 + Update: Add highConcurrencyStatus attribute to the
 SemaphoreValve to optionally allow the valve to return an error
 status code to the client when a permit cannot be acquired from the
 semaphore. (remm)
 + Add: Add checking of the 'age' of the running Tomcat instance
 since its build-date to the SecurityListener, and log a warning if
 the server is old. (schultz)
 + Fix: When using the AsyncContext, throw an
 IllegalStateException, rather than allowing an NullPointerException,
 if an attempt is made to use the AsyncContext after it has been
 recycled. (markt)
 + Fix: Correct JPMS and OSGi meta-data for tomcat-embed-core.jar
 by removing reference to org.apache.catalina.ssi package that is no
 longer included in the JAR. Based on pull request #684 by Jendrik
 Johannes. (markt)
 + Fix: Fix ServiceBindingPropertySource so that trailing \r\n
 sequences are correctly removed from files containing property values
 when configured to do so. Bug identified by Coverity Scan. (markt)
 + Add: Add improvements to the CSRF prevention filter including
 the ability to skip adding nonces for resource name and subtree URL
 patterns. (schultz)
 + Fix: Review usage ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'tomcat10' package(s) on openSUSE Leap 15.5.");

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

  if(!isnull(res = isrpmvuln(pkg:"tomcat10", rpm:"tomcat10~10.1.20~150200.5.22.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat10-admin-webapps", rpm:"tomcat10-admin-webapps~10.1.20~150200.5.22.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat10-docs-webapp", rpm:"tomcat10-docs-webapp~10.1.20~150200.5.22.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat10-el-5_0-api", rpm:"tomcat10-el-5_0-api~10.1.20~150200.5.22.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat10-embed", rpm:"tomcat10-embed~10.1.20~150200.5.22.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat10-jsp-3_1-api", rpm:"tomcat10-jsp-3_1-api~10.1.20~150200.5.22.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat10-jsvc", rpm:"tomcat10-jsvc~10.1.20~150200.5.22.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat10-lib", rpm:"tomcat10-lib~10.1.20~150200.5.22.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat10-servlet-6_0-api", rpm:"tomcat10-servlet-6_0-api~10.1.20~150200.5.22.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat10-webapps", rpm:"tomcat10-webapps~10.1.20~150200.5.22.2", rls:"openSUSELeap15.5"))) {
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
