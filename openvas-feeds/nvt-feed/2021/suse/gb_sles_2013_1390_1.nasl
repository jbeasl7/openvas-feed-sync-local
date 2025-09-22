# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2013.1390.1");
  script_cve_id("CVE-2013-1861", "CVE-2013-3783", "CVE-2013-3793", "CVE-2013-3794", "CVE-2013-3795", "CVE-2013-3796", "CVE-2013-3798", "CVE-2013-3801", "CVE-2013-3802", "CVE-2013-3804", "CVE-2013-3805", "CVE-2013-3806", "CVE-2013-3807", "CVE-2013-3808", "CVE-2013-3809", "CVE-2013-3810", "CVE-2013-3811", "CVE-2013-3812");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:23 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");

  script_name("SUSE: Security Advisory (SUSE-SU-2013:1390-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2013:1390-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2013/suse-su-20131390-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MySQL' package(s) announced via the SUSE-SU-2013:1390-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This version upgrade of mysql to 5.5.32 fixes multiple security issues:

CVE-2013-1861, CVE-2013-3783, CVE-2013-3793, CVE-2013-3794,
CVE-2013-3795, CVE-2013-3796, CVE-2013-3798,
CVE-2013-3801, CVE-2013-3802, CVE-2013-3804,
CVE-2013-3805, CVE-2013-3806, CVE-2013-3807, CVE-2013-3808,
CVE-2013-3809, CVE-2013-3810, CVE-2013-3811, CVE-2013-3812

Additionally, it contains numerous bug fixes and improvements.:

 * making mysqldump work with MySQL 5.0 (bnc#768832)
 * fixed log rights (bnc#789263 and bnc#803040)
 * binlog disabled in default configuration (bnc#791863)
 * fixed dependencies for client package (bnc#780019)
 * minor polishing of spec/installation
 * avoiding file conflicts with mytop
 * better fix for hardcoded libdir issue
 * fix hardcoded plugin paths (bnc#834028)
 * Use chown --no-dereference instead of chown to improve security (bnc#834967)
 * Adjust to spell !includedir correctly in /etc/my.cnf
(bnc#734436)

Security Issue references:

 * CVE-2013-1861
>
 * CVE-2013-3783
>
 * CVE-2013-3793
>
 * CVE-2013-3794
>
 * CVE-2013-3795
>
 * CVE-2013-3796
>
 * CVE-2013-3798
>
 * CVE-2013-3801
>
 * CVE-2013-3802
>
 * CVE-2013-3804
>
 * CVE-2013-3805
>
 * CVE-2013-3806
>
 * CVE-2013-3807
>
 * CVE-2013-3808
>
 * CVE-2013-3809
>
 * CVE-2013-3810
>
 * CVE-2013-3811
>
 * CVE-2013-3812
>");

  script_tag(name:"affected", value:"'MySQL' package(s) on SUSE Linux Enterprise Desktop 11-SP3, SUSE Linux Enterprise Server 11-SP3, SUSE Linux Enterprise Software Development Kit 11-SP3.");

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

if(release == "SLES11.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"libmysql55client18-32bit", rpm:"libmysql55client18-32bit~5.5.32~0.9.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysql55client18", rpm:"libmysql55client18~5.5.32~0.9.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysql55client18-x86", rpm:"libmysql55client18-x86~5.5.32~0.9.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysql55client_r18", rpm:"libmysql55client_r18~5.5.32~0.9.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysqlclient15-32bit", rpm:"libmysqlclient15-32bit~5.0.96~0.6.9", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysqlclient15", rpm:"libmysqlclient15~5.0.96~0.6.9", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysqlclient15-x86", rpm:"libmysqlclient15-x86~5.0.96~0.6.9", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysqlclient_r15", rpm:"libmysqlclient_r15~5.0.96~0.6.9", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql", rpm:"mysql~5.5.32~0.9.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-client", rpm:"mysql-client~5.5.32~0.9.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-tools", rpm:"mysql-tools~5.5.32~0.9.1", rls:"SLES11.0SP3"))) {
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
