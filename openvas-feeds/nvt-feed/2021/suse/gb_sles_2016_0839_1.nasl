# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.0839.1");
  script_cve_id("CVE-2015-5174", "CVE-2015-5345", "CVE-2016-0706", "CVE-2016-0714");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:07 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-03-01 15:37:11 +0000 (Tue, 01 Mar 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:0839-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:0839-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20160839-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/934219");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/967815");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/967964");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/967965");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/967967");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-March/001960.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tomcat6' package(s) announced via the SUSE-SU-2016:0839-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for tomcat6 fixes the following issues:

The version was updated from 6.0.41 to 6.0.45.

Security issues fixed:

* CVE-2015-5174: Directory traversal vulnerability in RequestUtil.java
 in Apache Tomcat allowed remote authenticated users to bypass intended
 SecurityManager restrictions and list a parent directory via a /.. (slash
 dot dot) in a pathname used by a web application in a getResource,
 getResourceAsStream, or getResourcePaths call, as demonstrated by the
 $CATALINA_BASE/webapps directory. (bsc#967967)
* CVE-2015-5345: The Mapper component in Apache Tomcat processes redirects
 before considering security constraints and Filters, which allowed remote
 attackers to determine the existence of a directory via a URL that lacks
 a trailing / (slash) character. (bsc#967965)
* CVE-2016-0706: Apache Tomcat did not place
 org.apache.catalina.manager.StatusManagerServlet on the
 org/apache/catalina/core/RestrictedServlets.properties list, which
 allowed remote authenticated users to bypass intended SecurityManager
 restrictions and read arbitrary HTTP requests, and consequently discover
 session ID values, via a crafted web application. (bsc#967815)
* CVE-2016-0714: The session-persistence implementation in Apache Tomcat
 mishandled session attributes, which allowed remote authenticated users
 to bypass intended SecurityManager restrictions and execute arbitrary
 code in a privileged context via a web application that places a crafted
 object in a session. (bsc#967964)");

  script_tag(name:"affected", value:"'tomcat6' package(s) on SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server for SAP Applications 11-SP4.");

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

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"tomcat6", rpm:"tomcat6~6.0.45~0.50.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat6-admin-webapps", rpm:"tomcat6-admin-webapps~6.0.45~0.50.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat6-docs-webapp", rpm:"tomcat6-docs-webapp~6.0.45~0.50.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat6-javadoc", rpm:"tomcat6-javadoc~6.0.45~0.50.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat6-jsp-2_1-api", rpm:"tomcat6-jsp-2_1-api~6.0.45~0.50.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat6-lib", rpm:"tomcat6-lib~6.0.45~0.50.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat6-servlet-2_5-api", rpm:"tomcat6-servlet-2_5-api~6.0.45~0.50.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat6-webapps", rpm:"tomcat6-webapps~6.0.45~0.50.1", rls:"SLES11.0SP4"))) {
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
