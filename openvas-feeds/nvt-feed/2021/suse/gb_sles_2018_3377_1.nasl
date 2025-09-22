# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.3377.1");
  script_cve_id("CVE-2018-10915", "CVE-2018-10925");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-18 16:57:10 +0000 (Thu, 18 Oct 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:3377-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0|SLES12\.0SP1|SLES12\.0SP2|SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:3377-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20183377-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104199");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104202");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-October/004778.html");
  script_xref(name:"URL", value:"https://www.postgresql.org/docs/current/static/release-9-6-10.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql96' package(s) announced via the SUSE-SU-2018:3377-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for postgresql96 to 9.6.10 fixes the following issues:

These security issues were fixed:

- CVE-2018-10915: libpq failed to properly reset its internal state between
 connections. If an affected version of libpq was used with 'host' or 'hostaddr'
 connection parameters from untrusted input, attackers could have bypassed
 client-side connection security features, obtain access to higher privileged
 connections or potentially cause other impact SQL injection, by causing the
 PQescape() functions to malfunction (bsc#1104199)
- CVE-2018-10925: Add missing authorization check on certain statements
 involved with 'INSERT ... ON CONFLICT DO UPDATE'. An attacker with 'CREATE
 TABLE' privileges could have exploited this to read arbitrary bytes server
 memory. If the attacker also had certain 'INSERT' and limited 'UPDATE'
 privileges to a particular table, they could have exploited this to update
 other columns in the same table (bsc#1104202)

For addition details please see [link moved to references]");

  script_tag(name:"affected", value:"'postgresql96' package(s) on SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for SAP Applications 12-SP1, SUSE Linux Enterprise Server for SAP Applications 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"postgresql96", rpm:"postgresql96~9.6.10~3.22.7", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-contrib", rpm:"postgresql96-contrib~9.6.10~3.22.7", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-docs", rpm:"postgresql96-docs~9.6.10~3.22.7", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-server", rpm:"postgresql96-server~9.6.10~3.22.7", rls:"SLES12.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"postgresql96", rpm:"postgresql96~9.6.10~3.22.7", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-contrib", rpm:"postgresql96-contrib~9.6.10~3.22.7", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-docs", rpm:"postgresql96-docs~9.6.10~3.22.7", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-server", rpm:"postgresql96-server~9.6.10~3.22.7", rls:"SLES12.0SP1"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"postgresql96", rpm:"postgresql96~9.6.10~3.22.7", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-contrib", rpm:"postgresql96-contrib~9.6.10~3.22.7", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-docs", rpm:"postgresql96-docs~9.6.10~3.22.7", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-server", rpm:"postgresql96-server~9.6.10~3.22.7", rls:"SLES12.0SP2"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"postgresql96", rpm:"postgresql96~9.6.10~3.22.7", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-contrib", rpm:"postgresql96-contrib~9.6.10~3.22.7", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-docs", rpm:"postgresql96-docs~9.6.10~3.22.7", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-server", rpm:"postgresql96-server~9.6.10~3.22.7", rls:"SLES12.0SP3"))) {
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
