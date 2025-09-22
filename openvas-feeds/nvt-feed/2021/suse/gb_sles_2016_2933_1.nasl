# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.2933.1");
  script_cve_id("CVE-2016-3492", "CVE-2016-5584", "CVE-2016-5616", "CVE-2016-5624", "CVE-2016-5626", "CVE-2016-5629", "CVE-2016-6663", "CVE-2016-7440", "CVE-2016-8283");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-22 17:12:58 +0000 (Thu, 22 Dec 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:2933-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP1|SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:2933-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20162933-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1001367");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1003800");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1004477");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1005555");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1005558");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1005562");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1005564");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1005566");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1005569");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1005581");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1005582");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1006539");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1008318");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/990890");
  script_xref(name:"URL", value:"https://kb.askmonty.org/en/mariadb-10028-changelog");
  script_xref(name:"URL", value:"https://kb.askmonty.org/en/mariadb-10028-release-notes");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-November/002425.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mariadb' package(s) announced via the SUSE-SU-2016:2933-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- CVE-2016-8283: Unspecified vulnerability in subcomponent Types (bsc#1005582)
- CVE-2016-7440: Unspecified vulnerability in subcomponent Encryption (bsc#1005581)
- CVE-2016-5629: Unspecified vulnerability in subcomponent Federated (bsc#1005569)
- CVE-2016-5626: Unspecified vulnerability in subcomponent GIS (bsc#1005566)
- CVE-2016-5624: Unspecified vulnerability in subcomponent DML (bsc#1005564)
- CVE-2016-5616: Unspecified vulnerability in subcomponent MyISAM (bsc#1005562)
- CVE-2016-5584: Unspecified vulnerability in subcomponent Encryption (bsc#1005558)
- CVE-2016-3492: Unspecified vulnerability in subcomponent Optimizer (bsc#1005555)
- CVE-2016-6663: Privilege Escalation / Race Condition (bsc#1001367)

Bugfixes:
- mysql_install_db can't find data files (bsc#1006539)
- mariadb failing test sys_vars.optimizer_switch_basic (bsc#1003800)
- Remove useless mysql@default.service (bsc#1004477)
- Replace all occurrences of the string '@sysconfdir@' with '/etc' as it wasn't expanded properly (bsc#990890)
- Notable changes:
 * XtraDB updated to 5.6.33-79.0
 * TokuDB updated to 5.6.33-79.0
 * Innodb updated to 5.6.33
 * Performance Schema updated to 5.6.33
- Release notes and upstream changelog:
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

  if(!isnull(res = isrpmvuln(pkg:"libmysqlclient18", rpm:"libmysqlclient18~10.0.28~17.2", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysqlclient18-32bit", rpm:"libmysqlclient18-32bit~10.0.28~17.2", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb", rpm:"mariadb~10.0.28~17.2", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-client", rpm:"mariadb-client~10.0.28~17.2", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-errormessages", rpm:"mariadb-errormessages~10.0.28~17.2", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-tools", rpm:"mariadb-tools~10.0.28~17.2", rls:"SLES12.0SP1"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"libmysqlclient18", rpm:"libmysqlclient18~10.0.28~17.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysqlclient18-32bit", rpm:"libmysqlclient18-32bit~10.0.28~17.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb", rpm:"mariadb~10.0.28~17.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-client", rpm:"mariadb-client~10.0.28~17.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-errormessages", rpm:"mariadb-errormessages~10.0.28~17.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-tools", rpm:"mariadb-tools~10.0.28~17.2", rls:"SLES12.0SP2"))) {
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
