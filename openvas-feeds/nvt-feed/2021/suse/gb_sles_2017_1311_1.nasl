# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.1311.1");
  script_cve_id("CVE-2017-3302", "CVE-2017-3313");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-02-16 14:24:57 +0000 (Thu, 16 Feb 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:1311-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:1311-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20171311-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1020890");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1020976");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1022428");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1034911");
  script_xref(name:"URL", value:"https://kb.askmonty.org/en/mariadb-10030-changelog");
  script_xref(name:"URL", value:"https://kb.askmonty.org/en/mariadb-10030-release-notes");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-May/002886.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mariadb' package(s) announced via the SUSE-SU-2017:1311-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for mariadb fixes the following issues:

- update to MariaDB 10.0.30 GA
 * notable changes:
 * XtraDB updated to 5.6.35-80.0
 * TokuDB updated to 5.6.35-80.0
 * PCRE updated to 8.40
 * MDEV-11027: better InnoDB crash recovery progress reporting
 * MDEV-11520: improvements to how InnoDB data files are extended
 * Improvements to InnoDB startup/shutdown to make it more robust
 * MDEV-11233: fix for FULLTEXT index crash
 * MDEV-6143: MariaDB Linux binary tarballs will now always untar
 to directories that match their filename
 * release notes and changelog:
 * [links moved to references]
 * fixes the following CVEs:
 CVE-2017-3313: unspecified vulnerability affecting the MyISAM component [bsc#1020890]
 CVE-2017-3302: Use after free in libmysqlclient.so [bsc#1022428]
- set the default umask to 077 in rc.mysql-multi [bsc#1020976]
- [bsc#1034911] - tracker bug
- increase build disk size from 10 GB to 13 GB in order to fix
 build for aarch64");

  script_tag(name:"affected", value:"'mariadb' package(s) on SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server for SAP Applications 12.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"libmysqlclient-devel", rpm:"libmysqlclient-devel~10.0.30~20.26.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysqlclient18", rpm:"libmysqlclient18~10.0.30~20.26.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysqlclient18-32bit", rpm:"libmysqlclient18-32bit~10.0.30~20.26.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysqlclient_r18", rpm:"libmysqlclient_r18~10.0.30~20.26.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysqld-devel", rpm:"libmysqld-devel~10.0.30~20.26.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysqld18", rpm:"libmysqld18~10.0.30~20.26.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb", rpm:"mariadb~10.0.30~20.26.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-client", rpm:"mariadb-client~10.0.30~20.26.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-errormessages", rpm:"mariadb-errormessages~10.0.30~20.26.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-tools", rpm:"mariadb-tools~10.0.30~20.26.1", rls:"SLES12.0"))) {
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
