# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.0555.1");
  script_cve_id("CVE-2016-9843", "CVE-2018-3058", "CVE-2018-3060", "CVE-2018-3063", "CVE-2018-3064", "CVE-2018-3066", "CVE-2018-3143", "CVE-2018-3156", "CVE-2018-3162", "CVE-2018-3173", "CVE-2018-3174", "CVE-2018-3185", "CVE-2018-3200", "CVE-2018-3251", "CVE-2018-3277", "CVE-2018-3282", "CVE-2018-3284", "CVE-2019-2510", "CVE-2019-2537");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:30 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-06-01 16:47:18 +0000 (Thu, 01 Jun 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:0555-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:0555-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20190555-1/");
  script_xref(name:"URL", value:"https://mariadb.com/kb/en/library/mariadb-10222-release-notes");
  script_xref(name:"URL", value:"https://mariadb.com/kb/en/library/mariadb-10222-changelog/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mariadb' package(s) announced via the SUSE-SU-2019:0555-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for mariadb to version 10.2.22 fixes the following issues:

Security issues fixed:
CVE-2019-2510: Fixed a vulnerability which can lead to MySQL compromise
 and lead to Denial of Service (bsc#1122198).

CVE-2019-2537: Fixed a vulnerability which can lead to MySQL compromise
 and lead to Denial of Service (bsc#1122198).

CVE-2018-3284: Fixed InnoDB unspecified vulnerability (CPU Oct 2018)
 (bsc#1112377)

CVE-2018-3282: Server Storage Engines unspecified vulnerability (CPU Oct
 2018) (bsc#1112432)

CVE-2018-3277: Fixed InnoDB unspecified vulnerability (CPU Oct 2018)
 (bsc#1112391)

CVE-2018-3251: InnoDB unspecified vulnerability (CPU Oct 2018)
 (bsc#1112397)

CVE-2018-3200: Fixed InnoDB unspecified vulnerability (CPU Oct 2018)
 (bsc#1112404)

CVE-2018-3185: Fixed InnoDB unspecified vulnerability (CPU Oct 2018)
 (bsc#1112384)

CVE-2018-3174: Client programs unspecified vulnerability (CPU Oct 2018)
 (bsc#1112368)

CVE-2018-3173: Fixed InnoDB unspecified vulnerability (CPU Oct 2018)
 (bsc#1112386)

CVE-2018-3162: Fixed InnoDB unspecified vulnerability (CPU Oct 2018)
 (bsc#1112415)

CVE-2018-3156: InnoDB unspecified vulnerability (CPU Oct 2018)
 (bsc#1112417)

CVE-2018-3143: InnoDB unspecified vulnerability (CPU Oct 2018)
 (bsc#1112421)

CVE-2018-3066: Unspecified vulnerability in the MySQL Server component
 of Oracle MySQL (subcomponent Server Options). (bsc#1101678)

CVE-2018-3064: InnoDB unspecified vulnerability (CPU Jul 2018)
 (bsc#1103342)

CVE-2018-3063: Unspecified vulnerability in the MySQL Server component
 of Oracle MySQL (subcomponent Server Security Privileges). (bsc#1101677)

CVE-2018-3058: Unspecified vulnerability in the MySQL Server component
 of Oracle MySQL (subcomponent MyISAM). (bsc#1101676)

CVE-2016-9843: Big-endian out-of-bounds pointer (bsc#1013882)

Non-security issues fixed:
Fixed an issue where mysl_install_db fails due to incorrect basedir
 (bsc#1127027).

Fixed an issue where the lograte was not working (bsc#1112767).

Backport Information Schema CHECK_CONSTRAINTS Table.

Maximum value of table_definition_cache is now 2097152.

InnoDB ALTER TABLE fixes.

Galera crash recovery fixes.

Encryption fixes.

Remove xtrabackup dependency as MariaDB ships a build in mariabackup so
 xtrabackup is not needed (bsc#1122475).

Maria DB testsuite - test main.plugin_auth failed (bsc#1111859)

Maria DB testsuite - test encryption.second_plugin-12863 failed
 (bsc#1111858)

Remove PerconaFT from the package as it has AGPL licence (bsc#1118754)

remove PerconaFT from the package as it has AGPL licence (bsc#1118754)

Database corruption after renaming a prefix-indexed column (bsc#1120041)


Release notes and changelog:
[link moved to references]

[link moved to references]");

  script_tag(name:"affected", value:"'mariadb' package(s) on SUSE Linux Enterprise Module for Open Buildservice Development Tools 15, SUSE Linux Enterprise Module for Server Applications 15.");

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

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"libmysqld-devel", rpm:"libmysqld-devel~10.2.22~3.14.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysqld19", rpm:"libmysqld19~10.2.22~3.14.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysqld19-debuginfo", rpm:"libmysqld19-debuginfo~10.2.22~3.14.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb", rpm:"mariadb~10.2.22~3.14.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-client", rpm:"mariadb-client~10.2.22~3.14.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-client-debuginfo", rpm:"mariadb-client-debuginfo~10.2.22~3.14.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-debuginfo", rpm:"mariadb-debuginfo~10.2.22~3.14.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-debugsource", rpm:"mariadb-debugsource~10.2.22~3.14.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-errormessages", rpm:"mariadb-errormessages~10.2.22~3.14.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-tools", rpm:"mariadb-tools~10.2.22~3.14.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-tools-debuginfo", rpm:"mariadb-tools-debuginfo~10.2.22~3.14.1", rls:"SLES15.0"))) {
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
