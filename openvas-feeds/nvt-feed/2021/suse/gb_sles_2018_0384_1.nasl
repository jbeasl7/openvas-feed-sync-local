# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.0384.1");
  script_cve_id("CVE-2017-10268", "CVE-2017-10378");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-10-24 19:05:41 +0000 (Tue, 24 Oct 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:0384-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2|SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:0384-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20180384-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1058722");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1064101");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1064115");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1076505");
  script_xref(name:"URL", value:"https://kb.askmonty.org/en/mariadb-10033-changelog");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-February/003712.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mariadb' package(s) announced via the SUSE-SU-2018:0384-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for mariadb to version 10.0.33 fixes several issues.

These security issues were fixed:

- CVE-2017-10378: Vulnerability in subcomponent: Server: Optimizer. Easily
 exploitable vulnerability allowed low privileged attacker with network access
 via multiple protocols to compromise MySQL Server. Successful attacks of this
 vulnerability can result in unauthorized ability to cause a hang or frequently
 repeatable crash (complete DOS) of MySQL Server (bsc#1064115).
- CVE-2017-10268: Vulnerability in subcomponent: Server: Replication. Difficult
 to exploit vulnerability allowed high privileged attacker with logon to the
 infrastructure where MySQL Server executes to compromise MySQL Server.
 Successful attacks of this vulnerability can result in unauthorized access to
 critical data or complete access to all MySQL Server accessible data
 (bsc#1064101).

These non-security issues were fixed:

- CHECK TABLE no longer returns an error when run on a CONNECT table
- 'Undo log record is too big.' error occurring in very narrow range of string
 lengths
- Race condition between INFORMATION_SCHEMA.INNODB_SYS_TABLESTATS and
 ALTER/DROP/TRUNCATE TABLE
- Wrong result after altering a partitioned table fixed bugs in InnoDB FULLTEXT
 INDEX
- InnoDB FTS duplicate key error
- InnoDB crash after failed ADD INDEX and table_definition_cache eviction
- fts_create_doc_id() unnecessarily allocates 8 bytes for every inserted row
- IMPORT TABLESPACE may corrupt ROW_FORMAT=REDUNDANT tables

For additional details please see [link moved to references]");

  script_tag(name:"affected", value:"'mariadb' package(s) on SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP3.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"libmysqlclient18", rpm:"libmysqlclient18~10.0.33~29.13.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysqlclient18-32bit", rpm:"libmysqlclient18-32bit~10.0.33~29.13.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb", rpm:"mariadb~10.0.33~29.13.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-client", rpm:"mariadb-client~10.0.33~29.13.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-errormessages", rpm:"mariadb-errormessages~10.0.33~29.13.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-tools", rpm:"mariadb-tools~10.0.33~29.13.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"libmysqlclient18", rpm:"libmysqlclient18~10.0.33~29.13.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysqlclient18-32bit", rpm:"libmysqlclient18-32bit~10.0.33~29.13.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb", rpm:"mariadb~10.0.33~29.13.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-client", rpm:"mariadb-client~10.0.33~29.13.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-errormessages", rpm:"mariadb-errormessages~10.0.33~29.13.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-tools", rpm:"mariadb-tools~10.0.33~29.13.1", rls:"SLES12.0SP3"))) {
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
