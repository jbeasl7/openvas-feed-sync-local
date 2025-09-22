# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123297");
  script_cve_id("CVE-2013-4002");
  script_tag(name:"creation_date", value:"2015-10-06 11:01:55 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");

  script_name("Oracle: Security Advisory (ELSA-2014-1319)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=(OracleLinux6|OracleLinux7)");

  script_xref(name:"Advisory-ID", value:"ELSA-2014-1319");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2014-1319.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xerces-j2' package(s) announced via the ELSA-2014-1319 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.11.0-17]
- Fix XML parsing bug (JAXP, 8017298)
- Resolves: CVE-2013-4002");

  script_tag(name:"affected", value:"'xerces-j2' package(s) on Oracle Linux 6, Oracle Linux 7.");

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

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"xerces-j2", rpm:"xerces-j2~2.7.1~12.7.el6_5", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xerces-j2-demo", rpm:"xerces-j2-demo~2.7.1~12.7.el6_5", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xerces-j2-javadoc-apis", rpm:"xerces-j2-javadoc-apis~2.7.1~12.7.el6_5", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xerces-j2-javadoc-impl", rpm:"xerces-j2-javadoc-impl~2.7.1~12.7.el6_5", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xerces-j2-javadoc-other", rpm:"xerces-j2-javadoc-other~2.7.1~12.7.el6_5", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xerces-j2-javadoc-xni", rpm:"xerces-j2-javadoc-xni~2.7.1~12.7.el6_5", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xerces-j2-scripts", rpm:"xerces-j2-scripts~2.7.1~12.7.el6_5", rls:"OracleLinux6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "OracleLinux7") {

  if(!isnull(res = isrpmvuln(pkg:"xerces-j2", rpm:"xerces-j2~2.11.0~17.el7_0", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xerces-j2-demo", rpm:"xerces-j2-demo~2.11.0~17.el7_0", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xerces-j2-javadoc", rpm:"xerces-j2-javadoc~2.11.0~17.el7_0", rls:"OracleLinux7"))) {
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
