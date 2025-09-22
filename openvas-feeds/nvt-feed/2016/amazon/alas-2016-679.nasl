# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.120669");
  script_cve_id("CVE-2015-5346", "CVE-2015-5351", "CVE-2016-0706", "CVE-2016-0714", "CVE-2016-0763");
  script_tag(name:"creation_date", value:"2016-03-31 05:02:12 +0000 (Thu, 31 Mar 2016)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-15 16:30:00 +0000 (Mon, 15 Apr 2019)");

  script_name("Amazon Linux: Security Advisory (ALAS-2016-679)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2016-679");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2016-679.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tomcat8' package(s) announced via the ALAS-2016-679 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"ResourceLinkFactory.setGlobalContext() is a public method and was discovered to be accessible by web applications running under a security manager without any checks. This allowed a malicious web application to inject a malicious global context that could in turn be used to disrupt other web applications and/or read and write data owned by other web applications. (CVE-2016-0763)

A session fixation vulnerability was discovered that might allow remote attackers to hijack web sessions by leveraging use of a requestedSessionSSL field for an unintended request when different session settings are used for deployments of multiple versions of the same web application. (CVE-2015-5346)

The Manager and Host Manager applications were discovered to establish sessions and send CSRF tokens for arbitrary new requests, which allows remote attackers to bypass a CSRF protection mechanism by using a token. (CVE-2015-5351)

The session-persistence implementation was discovered to mishandle session attributes, which allows remote authenticated users to bypass intended SecurityManager restrictions and execute arbitrary code in a privileged context via a web application that places a crafted object in a session. (CVE-2016-0714)

It was discovered that org.apache.catalina.manager.StatusManagerServlet was not placed on the org/apache/catalina/core/RestrictedServlets.properties list, which allows remote authenticated users to bypass intended SecurityManager restrictions and read arbitrary HTTP requests, and consequently discover session ID values, via a crafted web application. (CVE-2016-0706)");

  script_tag(name:"affected", value:"'tomcat8' package(s) on Amazon Linux.");

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

if(release == "AMAZON") {

  if(!isnull(res = isrpmvuln(pkg:"tomcat8", rpm:"tomcat8~8.0.32~1.59.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat8-admin-webapps", rpm:"tomcat8-admin-webapps~8.0.32~1.59.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat8-docs-webapp", rpm:"tomcat8-docs-webapp~8.0.32~1.59.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat8-el-3.0-api", rpm:"tomcat8-el-3.0-api~8.0.32~1.59.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat8-javadoc", rpm:"tomcat8-javadoc~8.0.32~1.59.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat8-jsp-2.3-api", rpm:"tomcat8-jsp-2.3-api~8.0.32~1.59.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat8-lib", rpm:"tomcat8-lib~8.0.32~1.59.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat8-log4j", rpm:"tomcat8-log4j~8.0.32~1.59.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat8-servlet-3.1-api", rpm:"tomcat8-servlet-3.1-api~8.0.32~1.59.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat8-webapps", rpm:"tomcat8-webapps~8.0.32~1.59.amzn1", rls:"AMAZON"))) {
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
