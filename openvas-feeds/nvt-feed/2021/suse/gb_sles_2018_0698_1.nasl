# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.0698.1");
  script_cve_id("CVE-2017-10268", "CVE-2017-10378", "CVE-2018-2562", "CVE-2018-2612", "CVE-2018-2622", "CVE-2018-2640", "CVE-2018-2665", "CVE-2018-2668");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-23 13:50:59 +0000 (Tue, 23 Jan 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:0698-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:0698-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20180698-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1064101");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1064115");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1072665");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1078431");
  script_xref(name:"URL", value:"https://kb.askmonty.org/en/mariadb-10033-changelog");
  script_xref(name:"URL", value:"https://kb.askmonty.org/en/mariadb-10034-changelog");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-March/003817.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mariadb' package(s) announced via the SUSE-SU-2018:0698-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for mariadb to 10.0.34 fixes several issues.

These security issues were fixed:

- CVE-2017-10378: Vulnerability in subcomponent: Server: Optimizer. Easily exploitable vulnerability allowed low privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) (bsc#1064115).
- CVE-2017-10268: Vulnerability in subcomponent: Server: Replication. Difficult to exploit vulnerability allowed high privileged attacker with logon to the infrastructure where MySQL Server executes to compromise MySQL Server. Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to all MySQL Server accessible data (bsc#1064101).
- CVE-2018-2562: Vulnerability in the MySQL Server subcomponent: Server : Partition. Easily exploitable vulnerability allowed low privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Server as well as unauthorized update, insert or delete access to some of MySQL Server accessible data.
- CVE-2018-2622: Vulnerability in the MySQL Server subcomponent: Server: DDL. Easily exploitable vulnerability allowed low privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Server.
- CVE-2018-2640: Vulnerability in the MySQL Server subcomponent: Server: Optimizer. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Server.
- CVE-2018-2665: Vulnerability in the MySQL Server subcomponent: Server: Optimizer. Easily exploitable vulnerability allowed low privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Server.
- CVE-2018-2668: Vulnerability in the MySQL Server subcomponent: Server: Optimizer. Easily exploitable vulnerability allowed low privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Server.
- CVE-2018-2612: Vulnerability in the MySQL Server subcomponent: InnoDB. Easily exploitable vulnerability allowed high privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this vulnerability can ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'mariadb' package(s) on SUSE Linux Enterprise Server 12.");

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

  if(!isnull(res = isrpmvuln(pkg:"libmysqlclient-devel", rpm:"libmysqlclient-devel~10.0.34~20.43.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysqlclient18", rpm:"libmysqlclient18~10.0.34~20.43.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysqlclient18-32bit", rpm:"libmysqlclient18-32bit~10.0.34~20.43.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysqlclient_r18", rpm:"libmysqlclient_r18~10.0.34~20.43.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysqld-devel", rpm:"libmysqld-devel~10.0.34~20.43.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysqld18", rpm:"libmysqld18~10.0.34~20.43.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb", rpm:"mariadb~10.0.34~20.43.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-client", rpm:"mariadb-client~10.0.34~20.43.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-errormessages", rpm:"mariadb-errormessages~10.0.34~20.43.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-tools", rpm:"mariadb-tools~10.0.34~20.43.1", rls:"SLES12.0"))) {
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
