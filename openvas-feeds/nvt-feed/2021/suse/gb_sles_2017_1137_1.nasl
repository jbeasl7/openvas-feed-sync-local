# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.1137.1");
  script_cve_id("CVE-2016-5483", "CVE-2017-3302", "CVE-2017-3305", "CVE-2017-3308", "CVE-2017-3309", "CVE-2017-3329", "CVE-2017-3453", "CVE-2017-3456", "CVE-2017-3461", "CVE-2017-3462", "CVE-2017-3463", "CVE-2017-3464", "CVE-2017-3600");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:59 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-05-04 13:06:46 +0000 (Thu, 04 May 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:1137-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:1137-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20171137-1.html");
  script_xref(name:"URL", value:"http://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-55.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1020976");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1022428");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1029014");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1029396");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1034850");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-April/002833.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mysql' package(s) announced via the SUSE-SU-2017:1137-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for mysql to version 5.5.55 fixes the following issues:

These security issues were fixed:

- CVE-2017-3308: Unspecified vulnerability in Server: DML (bsc#1034850)
- CVE-2017-3309: Unspecified vulnerability in Server: Optimizer (bsc#1034850)
- CVE-2017-3329: Unspecified vulnerability in Server: Thread (bsc#1034850)
- CVE-2017-3600: Unspecified vulnerability in Client: mysqldump (bsc#1034850)
- CVE-2017-3453: Unspecified vulnerability in Server: Optimizer (bsc#1034850)
- CVE-2017-3456: Unspecified vulnerability in Server: DML (bsc#1034850)
- CVE-2017-3463: Unspecified vulnerability in Server: Security (bsc#1034850)
- CVE-2017-3462: Unspecified vulnerability in Server: Security (bsc#1034850)
- CVE-2017-3461: Unspecified vulnerability in Server: Security (bsc#1034850)
- CVE-2017-3464: Unspecified vulnerability in Server: DDL (bsc#1034850)
- CVE-2017-3305: MySQL client sent authentication request unencrypted even if SSL was required (aka Ridddle) (bsc#1029396).
- CVE-2016-5483: Mysqldump failed to properly quote certain identifiers in SQL statements written to the dump output, allowing for execution of arbitrary commands (bsc#1029014)
- '--ssl-mode=REQUIRED' can be specified to require a secure connection (it fails if a secure connection cannot be obtained)

This non-security issue was fixed:

- Set the default umask to 077 in rc.mysql-multi [bsc#1020976]

For additional changes please see [link moved to references]

Note: The issue tracked in bsc#1022428 and fixed in the last update was assigned CVE-2017-3302.");

  script_tag(name:"affected", value:"'mysql' package(s) on SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server for SAP Applications 11-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"libmysql55client18-32bit", rpm:"libmysql55client18-32bit~5.5.55~0.38.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysql55client18", rpm:"libmysql55client18~5.5.55~0.38.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysql55client18-x86", rpm:"libmysql55client18-x86~5.5.55~0.38.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysql55client_r18-32bit", rpm:"libmysql55client_r18-32bit~5.5.55~0.38.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysql55client_r18", rpm:"libmysql55client_r18~5.5.55~0.38.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysql55client_r18-x86", rpm:"libmysql55client_r18-x86~5.5.55~0.38.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql", rpm:"mysql~5.5.55~0.38.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-client", rpm:"mysql-client~5.5.55~0.38.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-tools", rpm:"mysql-tools~5.5.55~0.38.1", rls:"SLES11.0SP4"))) {
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
