# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856091");
  script_cve_id("CVE-2024-23672", "CVE-2024-24549");
  script_tag(name:"creation_date", value:"2024-04-23 01:01:52 +0000 (Tue, 23 Apr 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:1345-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1345-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20241345-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221385");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221386");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-April/018380.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tomcat' package(s) announced via the SUSE-SU-2024:1345-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for tomcat fixes the following issues:

- CVE-2024-24549: Fixed denial of service during header validation for HTTP/2 stream (bsc#1221386)
- CVE-2024-23672: Fixed denial of service due to malicious WebSocket client keeping connection open (bsc#1221385)

Other fixes:
- Update to Tomcat 9.0.87
 * Catalina
 + Fix: Minor performance improvement for building filter chains. Based
 on ideas from #702 by Luke Miao. (remm)
 + Fix: Align error handling for Writer and OutputStream. Ensure use of
 either once the response has been recycled triggers a
 NullPointerException provided that discardFacades is configured with
 the default value of true. (markt)
 + Fix: 68692: The standard thread pool implementations that are configured
 using the Executor element now implement ExecutorService for better
 support NIO2. (remm)
 + Fix: 68495: When restoring a saved POST request after a successful FORM
 authentication, ensure that neither the URI, the query string nor the
 protocol are corrupted when restoring the request body. (markt)
 + Fix: 68721: Workaround a possible cause of duplicate class definitions
 when using ClassFileTransformers and the transformation of a class also
 triggers the loading of the same class. (markt)
 + Fix: The rewrite valve should not do a rewrite if the output is
 identical to the input. (remm)
 + Update: Add a new valveSkip (or VS) rule flag to the rewrite valve to
 allow skipping over the next valve in the Catalina pipeline. (remm)
 + Fix: Correct JPMS and OSGi meta-data for tomcat-enbed-core.jar by
 removing reference to org.apache.catalina.ssi package that is no longer
 included in the JAR. Based on pull request #684 by Jendrik Johannes.
 (markt)
 + Fix: Fix ServiceBindingPropertySource so that trailing \r\n sequences
 are correctly removed from files containing property values when
 configured to do so. Bug identified by Coverity Scan. (markt)
 + Add: Add improvements to the CSRF prevention filter including the
 ability to skip adding nonces for resource name and subtree URL patterns.
 (schultz)
 + Fix: Review usage of debug logging and downgrade trace or data dumping
 operations from debug level to trace. (remm)
 + Fix: 68089: Further improve the performance of request attribute
 access for ApplicationHttpRequest and ApplicationRequest. (markt)
 + Fix: 68559: Allow asynchronous error handling to write to the
 response after an error during asynchronous processing. (markt)
 * Coyote
 + Fix: Improve the HTTP/2 stream prioritisation process. If a stream
 uses all of the connection windows and still has content to write, it
 will now be added to the backlog immediately rather than waiting until
 the write attempt for the remaining content. (markt)
 + Fix: Make asynchronous error handling more robust. Ensure that once
 a connection is marked to be closed, further asynchronous processing
 cannot change that. (markt)
 + Fix: Make asynchronous error ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'tomcat' package(s) on openSUSE Leap 15.5.");

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

  if(!isnull(res = isrpmvuln(pkg:"apache-commons-daemon", rpm:"apache-commons-daemon~1.3.4~150200.11.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-commons-daemon-javadoc", rpm:"apache-commons-daemon-javadoc~1.3.4~150200.11.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-commons-daemon-jsvc", rpm:"apache-commons-daemon-jsvc~1.3.4~150200.11.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-commons-dbcp", rpm:"apache-commons-dbcp~2.1.1~150200.10.8.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-commons-dbcp-javadoc", rpm:"apache-commons-dbcp-javadoc~2.1.1~150200.10.8.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-commons-pool2", rpm:"apache-commons-pool2~2.4.2~150200.11.8.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-commons-pool2-javadoc", rpm:"apache-commons-pool2-javadoc~2.4.2~150200.11.8.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"geronimo-annotation-1_0-api", rpm:"geronimo-annotation-1_0-api~1.2~150200.15.8.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"geronimo-commonj-1_1-apis", rpm:"geronimo-commonj-1_1-apis~1.2~150200.15.8.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"geronimo-corba-1_0-apis", rpm:"geronimo-corba-1_0-apis~1.2~150200.15.8.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"geronimo-corba-2_3-apis", rpm:"geronimo-corba-2_3-apis~1.2~150200.15.8.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"geronimo-ejb-2_1-api", rpm:"geronimo-ejb-2_1-api~1.2~150200.15.8.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"geronimo-ejb-3_0-api", rpm:"geronimo-ejb-3_0-api~1.2~150200.15.8.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"geronimo-el-1_0-api", rpm:"geronimo-el-1_0-api~1.2~150200.15.8.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"geronimo-interceptor-3_0-api", rpm:"geronimo-interceptor-3_0-api~1.2~150200.15.8.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"geronimo-j2ee-1_4-apis", rpm:"geronimo-j2ee-1_4-apis~1.2~150200.15.8.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"geronimo-j2ee-connector-1_5-api", rpm:"geronimo-j2ee-connector-1_5-api~1.2~150200.15.8.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"geronimo-j2ee-deployment-1_1-api", rpm:"geronimo-j2ee-deployment-1_1-api~1.2~150200.15.8.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"geronimo-j2ee-management-1_0-api", rpm:"geronimo-j2ee-management-1_0-api~1.2~150200.15.8.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"geronimo-j2ee-management-1_1-api", rpm:"geronimo-j2ee-management-1_1-api~1.2~150200.15.8.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"geronimo-jacc-1_0-api", rpm:"geronimo-jacc-1_0-api~1.2~150200.15.8.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"geronimo-jacc-1_1-api", rpm:"geronimo-jacc-1_1-api~1.2~150200.15.8.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"geronimo-jaf-1_0_2-api", rpm:"geronimo-jaf-1_0_2-api~1.2~150200.15.8.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"geronimo-jaf-1_1-api", rpm:"geronimo-jaf-1_1-api~1.2~150200.15.8.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"geronimo-javaee-deployment-1_1-api", rpm:"geronimo-javaee-deployment-1_1-api~1.2~150200.15.8.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"geronimo-javamail-1_3_1-api", rpm:"geronimo-javamail-1_3_1-api~1.2~150200.15.8.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"geronimo-javamail-1_4-api", rpm:"geronimo-javamail-1_4-api~1.2~150200.15.8.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"geronimo-jaxr-1_0-api", rpm:"geronimo-jaxr-1_0-api~1.2~150200.15.8.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"geronimo-jaxrpc-1_1-api", rpm:"geronimo-jaxrpc-1_1-api~1.2~150200.15.8.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"geronimo-jms-1_1-api", rpm:"geronimo-jms-1_1-api~1.2~150200.15.8.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"geronimo-jpa-3_0-api", rpm:"geronimo-jpa-3_0-api~1.2~150200.15.8.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"geronimo-jsp-2_0-api", rpm:"geronimo-jsp-2_0-api~1.2~150200.15.8.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"geronimo-jsp-2_1-api", rpm:"geronimo-jsp-2_1-api~1.2~150200.15.8.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"geronimo-jta-1_0_1B-api", rpm:"geronimo-jta-1_0_1B-api~1.2~150200.15.8.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"geronimo-jta-1_1-api", rpm:"geronimo-jta-1_1-api~1.2~150200.15.8.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"geronimo-qname-1_1-api", rpm:"geronimo-qname-1_1-api~1.2~150200.15.8.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"geronimo-saaj-1_1-api", rpm:"geronimo-saaj-1_1-api~1.2~150200.15.8.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"geronimo-servlet-2_4-api", rpm:"geronimo-servlet-2_4-api~1.2~150200.15.8.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"geronimo-servlet-2_5-api", rpm:"geronimo-servlet-2_5-api~1.2~150200.15.8.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"geronimo-stax-1_0-api", rpm:"geronimo-stax-1_0-api~1.2~150200.15.8.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"geronimo-ws-metadata-2_0-api", rpm:"geronimo-ws-metadata-2_0-api~1.2~150200.15.8.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jakarta-taglibs-standard", rpm:"jakarta-taglibs-standard~1.1.1~150000.4.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jakarta-taglibs-standard-javadoc", rpm:"jakarta-taglibs-standard-javadoc~1.1.1~150000.4.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat", rpm:"tomcat~9.0.87~150200.65.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-admin-webapps", rpm:"tomcat-admin-webapps~9.0.87~150200.65.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-docs-webapp", rpm:"tomcat-docs-webapp~9.0.87~150200.65.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-el-3_0-api", rpm:"tomcat-el-3_0-api~9.0.87~150200.65.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-embed", rpm:"tomcat-embed~9.0.87~150200.65.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-javadoc", rpm:"tomcat-javadoc~9.0.87~150200.65.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-jsp-2_3-api", rpm:"tomcat-jsp-2_3-api~9.0.87~150200.65.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-jsvc", rpm:"tomcat-jsvc~9.0.87~150200.65.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-lib", rpm:"tomcat-lib~9.0.87~150200.65.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-servlet-4_0-api", rpm:"tomcat-servlet-4_0-api~9.0.87~150200.65.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-webapps", rpm:"tomcat-webapps~9.0.87~150200.65.1", rls:"openSUSELeap15.5"))) {
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
