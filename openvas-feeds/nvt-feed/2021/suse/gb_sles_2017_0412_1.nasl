# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.0412.1");
  script_cve_id("CVE-2016-6664", "CVE-2017-3238", "CVE-2017-3243", "CVE-2017-3244", "CVE-2017-3257", "CVE-2017-3258", "CVE-2017-3265", "CVE-2017-3291", "CVE-2017-3312", "CVE-2017-3317", "CVE-2017-3318");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-19 14:51:30 +0000 (Mon, 19 Dec 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:0412-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP1|SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:0412-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20170412-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1008253");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1020868");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1020873");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1020875");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1020877");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1020878");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1020882");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1020884");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1020885");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1020891");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1020894");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1020896");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1022428");
  script_xref(name:"URL", value:"https://kb.askmonty.org/en/mariadb-10029-changelog");
  script_xref(name:"URL", value:"https://kb.askmonty.org/en/mariadb-10029-release-notes");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-February/002629.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mariadb' package(s) announced via the SUSE-SU-2017:0412-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This mariadb version update to 10.0.29 fixes the following issues:

- CVE-2017-3318: unspecified vulnerability affecting Error Handling (bsc#1020896)
- CVE-2017-3317: unspecified vulnerability affecting Logging (bsc#1020894)
- CVE-2017-3312: insecure error log file handling in mysqld_safe, incomplete CVE-2016-6664 (bsc#1020873)
- CVE-2017-3291: unrestricted mysqld_safe's ledir (bsc#1020884)
- CVE-2017-3265: unsafe chmod/chown use in init script (bsc#1020885)
- CVE-2017-3258: unspecified vulnerability in the DDL component (bsc#1020875)
- CVE-2017-3257: unspecified vulnerability affecting InnoDB (bsc#1020878)
- CVE-2017-3244: unspecified vulnerability affecing the DML component (bsc#1020877)
- CVE-2017-3243: unspecified vulnerability affecting the Charsets component (bsc#1020891)
- CVE-2017-3238: unspecified vulnerability affecting the Optimizer component (bsc#1020882)
- CVE-2016-6664: Root Privilege Escalation (bsc#1008253)
- Applications using the client library for MySQL (libmysqlclient.so) had a use-after-free issue that could cause the applications to crash (bsc#1022428)

- notable changes:
 * XtraDB updated to 5.6.34-79.1
 * TokuDB updated to 5.6.34-79.1
 * Innodb updated to 5.6.35
 * Performance Schema updated to 5.6.35

Release notes and changelog:
 * [links moved to references]");

  script_tag(name:"affected", value:"'mariadb' package(s) on SUSE Linux Enterprise Desktop 12-SP1, SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP1, SUSE Linux Enterprise Server for SAP Applications 12-SP2.");

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

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"libmysqlclient18", rpm:"libmysqlclient18~10.0.29~22.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysqlclient18-32bit", rpm:"libmysqlclient18-32bit~10.0.29~22.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb", rpm:"mariadb~10.0.29~22.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-client", rpm:"mariadb-client~10.0.29~22.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-errormessages", rpm:"mariadb-errormessages~10.0.29~22.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-tools", rpm:"mariadb-tools~10.0.29~22.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"libmysqlclient18", rpm:"libmysqlclient18~10.0.29~22.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysqlclient18-32bit", rpm:"libmysqlclient18-32bit~10.0.29~22.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb", rpm:"mariadb~10.0.29~22.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-client", rpm:"mariadb-client~10.0.29~22.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-errormessages", rpm:"mariadb-errormessages~10.0.29~22.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-tools", rpm:"mariadb-tools~10.0.29~22.1", rls:"SLES12.0SP2"))) {
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
