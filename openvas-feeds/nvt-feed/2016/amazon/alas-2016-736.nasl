# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.120725");
  script_cve_id("CVE-2016-3092");
  script_tag(name:"creation_date", value:"2016-10-26 12:38:21 +0000 (Wed, 26 Oct 2016)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-17 08:15:00 +0000 (Sat, 17 Jul 2021)");

  script_name("Amazon Linux: Security Advisory (ALAS-2016-736)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2016-736");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2016-736.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tomcat7, tomcat8' package(s) announced via the ALAS-2016-736 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A denial of service vulnerability was identified in Commons FileUpload that occurred when the length of the multipart boundary was just below the size of the buffer (4096 bytes) used to read the uploaded file if the boundary was the typical tens of bytes long.");

  script_tag(name:"affected", value:"'tomcat7, tomcat8' package(s) on Amazon Linux.");

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

  if(!isnull(res = isrpmvuln(pkg:"tomcat7", rpm:"tomcat7~7.0.70~1.18.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat7-admin-webapps", rpm:"tomcat7-admin-webapps~7.0.70~1.18.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat7-docs-webapp", rpm:"tomcat7-docs-webapp~7.0.70~1.18.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat7-el-2.2-api", rpm:"tomcat7-el-2.2-api~7.0.70~1.18.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat7-javadoc", rpm:"tomcat7-javadoc~7.0.70~1.18.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat7-jsp-2.2-api", rpm:"tomcat7-jsp-2.2-api~7.0.70~1.18.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat7-lib", rpm:"tomcat7-lib~7.0.70~1.18.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat7-log4j", rpm:"tomcat7-log4j~7.0.70~1.18.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat7-servlet-3.0-api", rpm:"tomcat7-servlet-3.0-api~7.0.70~1.18.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat7-webapps", rpm:"tomcat7-webapps~7.0.70~1.18.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat8", rpm:"tomcat8~8.0.36~1.62.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat8-admin-webapps", rpm:"tomcat8-admin-webapps~8.0.36~1.62.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat8-docs-webapp", rpm:"tomcat8-docs-webapp~8.0.36~1.62.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat8-el-3.0-api", rpm:"tomcat8-el-3.0-api~8.0.36~1.62.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat8-javadoc", rpm:"tomcat8-javadoc~8.0.36~1.62.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat8-jsp-2.3-api", rpm:"tomcat8-jsp-2.3-api~8.0.36~1.62.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat8-lib", rpm:"tomcat8-lib~8.0.36~1.62.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat8-log4j", rpm:"tomcat8-log4j~8.0.36~1.62.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat8-servlet-3.1-api", rpm:"tomcat8-servlet-3.1-api~8.0.36~1.62.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat8-webapps", rpm:"tomcat8-webapps~8.0.36~1.62.amzn1", rls:"AMAZON"))) {
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
