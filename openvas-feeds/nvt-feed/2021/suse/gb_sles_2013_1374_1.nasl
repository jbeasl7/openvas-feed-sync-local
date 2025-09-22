# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2013.1374.1");
  script_cve_id("CVE-2012-0022", "CVE-2012-3544", "CVE-2013-1976");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:23 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("SUSE: Security Advisory (SUSE-SU-2013:1374-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP2|SLES11\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2013:1374-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2013/suse-su-20131374-1/");
  script_xref(name:"URL", value:"http://youtrack.jetbrains.com/issue/JT-18545");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tomcat6' package(s) announced via the SUSE-SU-2013:1374-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update of tomcat6 fixes:

 * apache-tomcat-CVE-2012-3544.patch (bnc#831119)
 * use chown --no-dereference to prevent symlink attacks on log (bnc#822177#c7/prevents CVE-2013-1976)
 * Fix tomcat init scripts generating malformed classpath ( [link moved to references] ) bnc#804992
(patch from m407)
 * fix a typo in initscript (bnc#768772 )
 * copy all shell scripts (bnc#818948)
Security Issue references:
 * CVE-2012-3544
>
 * CVE-2013-1976
>
 * CVE-2012-0022
>");

  script_tag(name:"affected", value:"'tomcat6' package(s) on SUSE Linux Enterprise Server 11-SP2, SUSE Linux Enterprise Server 11-SP3, SUSE Manager 1.2.");

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

if(release == "SLES11.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"tomcat6", rpm:"tomcat6~6.0.18~20.35.42.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat6-admin-webapps", rpm:"tomcat6-admin-webapps~6.0.18~20.35.42.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat6-docs-webapp", rpm:"tomcat6-docs-webapp~6.0.18~20.35.42.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat6-javadoc", rpm:"tomcat6-javadoc~6.0.18~20.35.42.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat6-jsp-2_1-api", rpm:"tomcat6-jsp-2_1-api~6.0.18~20.35.42.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat6-lib", rpm:"tomcat6-lib~6.0.18~20.35.42.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat6-servlet-2_5-api", rpm:"tomcat6-servlet-2_5-api~6.0.18~20.35.42.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat6-webapps", rpm:"tomcat6-webapps~6.0.18~20.35.42.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"tomcat6", rpm:"tomcat6~6.0.18~20.35.42.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat6-admin-webapps", rpm:"tomcat6-admin-webapps~6.0.18~20.35.42.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat6-docs-webapp", rpm:"tomcat6-docs-webapp~6.0.18~20.35.42.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat6-javadoc", rpm:"tomcat6-javadoc~6.0.18~20.35.42.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat6-jsp-2_1-api", rpm:"tomcat6-jsp-2_1-api~6.0.18~20.35.42.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat6-lib", rpm:"tomcat6-lib~6.0.18~20.35.42.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat6-servlet-2_5-api", rpm:"tomcat6-servlet-2_5-api~6.0.18~20.35.42.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat6-webapps", rpm:"tomcat6-webapps~6.0.18~20.35.42.1", rls:"SLES11.0SP3"))) {
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
