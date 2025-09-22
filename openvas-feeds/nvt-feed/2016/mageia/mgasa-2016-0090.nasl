# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131247");
  script_cve_id("CVE-2015-5174", "CVE-2015-5345", "CVE-2015-5346", "CVE-2015-5351", "CVE-2016-0706", "CVE-2016-0714", "CVE-2016-0763");
  script_tag(name:"creation_date", value:"2016-03-03 12:39:17 +0000 (Thu, 03 Mar 2016)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-03-01 16:18:44 +0000 (Tue, 01 Mar 2016)");

  script_name("Mageia: Security Advisory (MGASA-2016-0090)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0090");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0090.html");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-7.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=17847");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tomcat, tomcat-native' package(s) announced via the MGASA-2016-0090 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated tomcat packages fix security vulnerabilities:

Directory traversal vulnerability in RequestUtil.java in Apache Tomcat 7.x
before 7.0.65 allows remote authenticated users to bypass intended
SecurityManager restrictions and list a parent directory via a /.. (slash dot
dot) in a pathname used by a web application in a getResource,
getResourceAsStream, or getResourcePaths call, as demonstrated by the
$CATALINA_BASE/webapps directory (CVE-2015-5174).

The Mapper component in 7.x before 7.0.67 processes redirects before
considering security constraints and Filters, which allows remote attackers
to determine the existence of a directory via a URL that lacks a trailing /
(slash) character (CVE-2015-5345).

Session fixation vulnerability in Apache Tomcat 7.x before 7.0.66, when
different session settings are used for deployments of multiple versions of
the same web application, might allow remote attackers to hijack web sessions
by leveraging use of a requestedSessionSSL field for an unintended request,
related to CoyoteAdapter.java and Request.java (CVE-2015-5346).

The Manager and Host Manager applications in Apache Tomcat 7.x before 7.0.68
establish sessions and send CSRF tokens for arbitrary new requests, which
allows remote attackers to bypass a CSRF protection mechanism by using a
token (CVE-2015-5351).

Apache Tomcat 7.x before 7.0.68 does not place
org.apache.catalina.manager.StatusManagerServlet on the
org/apache/catalina/core/RestrictedServlets.properties list, which allows
remote authenticated users to bypass intended SecurityManager restrictions
and read arbitrary HTTP requests, and consequently discover session ID
values, via a crafted web application (CVE-2016-0706).

The session-persistence implementation in Apache Tomcat 7.x before 7.0.68
mishandles session attributes, which allows remote authenticated users to
bypass intended SecurityManager restrictions and execute arbitrary code in a
privileged context via a web application that places a crafted object in a
session (CVE-2016-0714).

The setGlobalContext method in
org/apache/naming/factory/ResourceLinkFactory.java in Apache Tomcat 7.x
before 7.0.68 does not consider whether ResourceLinkFactory.setGlobalContext
callers are authorized, which allows remote authenticated users to bypass
intended SecurityManager restrictions and read or write to arbitrary
application data, or cause a denial of service (application disruption), via
a web application that sets a crafted global context (CVE-2016-0763).

The tomcat package has been updated to version 7.0.68 to fix these issues.
The tomcat-native package has also been updated to version 1.1.34 for
compatibility with the updated tomcat.");

  script_tag(name:"affected", value:"'tomcat, tomcat-native' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"lib64tcnative1", rpm:"lib64tcnative1~1.1.34~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64tcnative1-devel", rpm:"lib64tcnative1-devel~1.1.34~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtcnative1", rpm:"libtcnative1~1.1.34~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtcnative1-devel", rpm:"libtcnative1-devel~1.1.34~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat", rpm:"tomcat~7.0.68~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-admin-webapps", rpm:"tomcat-admin-webapps~7.0.68~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-docs-webapp", rpm:"tomcat-docs-webapp~7.0.68~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-el-2.2-api", rpm:"tomcat-el-2.2-api~7.0.68~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-javadoc", rpm:"tomcat-javadoc~7.0.68~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-jsp-2.2-api", rpm:"tomcat-jsp-2.2-api~7.0.68~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-jsvc", rpm:"tomcat-jsvc~7.0.68~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-lib", rpm:"tomcat-lib~7.0.68~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-native", rpm:"tomcat-native~1.1.34~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-servlet-3.0-api", rpm:"tomcat-servlet-3.0-api~7.0.68~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-webapps", rpm:"tomcat-webapps~7.0.68~1.mga5", rls:"MAGEIA5"))) {
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
