# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.4211.1");
  script_cve_id("CVE-2016-9843", "CVE-2018-3058", "CVE-2018-3063", "CVE-2018-3064", "CVE-2018-3066", "CVE-2018-3143", "CVE-2018-3156", "CVE-2018-3174", "CVE-2018-3251", "CVE-2018-3282");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-06-01 16:47:18 +0000 (Thu, 01 Jun 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:4211-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:4211-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20184211-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1013882");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1101676");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1101677");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1101678");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1103342");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112368");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112397");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112417");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112421");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112432");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1116686");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118754");
  script_xref(name:"URL", value:"https://kb.askmonty.org/en/mariadb-10036-changelog");
  script_xref(name:"URL", value:"https://kb.askmonty.org/en/mariadb-10036-release-notes");
  script_xref(name:"URL", value:"https://kb.askmonty.org/en/mariadb-10037-changelog");
  script_xref(name:"URL", value:"https://kb.askmonty.org/en/mariadb-10037-release-notes");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-December/004993.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mariadb' package(s) announced via the SUSE-SU-2018:4211-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for mariadb fixes the following issues:

Update to MariaDB 10.0.37 GA (bsc#1116686).

Security issues fixed:

- CVE-2018-3282: Server Storage Engines unspecified vulnerability (CPU Oct 2018) (bsc#1112432)
- CVE-2018-3251: InnoDB unspecified vulnerability (CPU Oct 2018) (bsc#1112397)
- CVE-2018-3174: Client programs unspecified vulnerability (CPU Oct 2018) (bsc#1112368)
- CVE-2018-3156: InnoDB unspecified vulnerability (CPU Oct 2018) (bsc#1112417)
- CVE-2018-3143: InnoDB unspecified vulnerability (CPU Oct 2018) (bsc#1112421)
- CVE-2018-3066: Unspecified vulnerability in the MySQL Server component of Oracle MySQL (subcomponent Server Options). (bsc#1101678)
- CVE-2018-3064: InnoDB unspecified vulnerability (CPU Jul 2018) (bsc#1103342)
- CVE-2018-3063: Unspecified vulnerability in the MySQL Server component of Oracle MySQL (subcomponent Server Security Privileges). (bsc#1101677)
- CVE-2018-3058: Unspecified vulnerability in the MySQL Server component of Oracle MySQL (subcomponent MyISAM). (bsc#1101676)
- CVE-2016-9843: Big-endian out-of-bounds pointer (bsc#1013882)

Non-security changes:

- Remove PerconaFT from the package as it has AGPL licence (bsc#1118754)
- do not just remove tokudb plugin but don't build it at all (missing jemalloc dependency)

Release notes and changelog:

- [links moved to references]");

  script_tag(name:"affected", value:"'mariadb' package(s) on SUSE Linux Enterprise Desktop 12-SP4, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server for SAP Applications 12-SP4.");

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

if(release == "SLES12.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"libmysqlclient18", rpm:"libmysqlclient18~10.0.37~2.3.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysqlclient18-32bit", rpm:"libmysqlclient18-32bit~10.0.37~2.3.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-100-errormessages", rpm:"mariadb-100-errormessages~10.0.37~2.3.1", rls:"SLES12.0SP4"))) {
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
