# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.0900.1");
  script_cve_id("CVE-2019-3814", "CVE-2019-7524");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-29 13:55:52 +0000 (Fri, 29 Mar 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:0900-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0|SLES12\.0SP1|SLES12\.0SP2|SLES12\.0SP3|SLES12\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:0900-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20190900-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1111789");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1123022");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1130116");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2019-April/005310.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dovecot22' package(s) announced via the SUSE-SU-2019:0900-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for dovecot22 fixes the following issues:

Security issues fixed:

- CVE-2019-7524: Fixed an improper file handling which could result in stack overflow allowing
 local root escalation (bsc#1130116).
- CVE-2019-3814: Fixed a vulnerability related to SSL client certificate authentication (bsc#1123022).

Other issue fixed:
- Fixed handling of command continuation(bsc#1111789)");

  script_tag(name:"affected", value:"'dovecot22' package(s) on SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server for SAP Applications 12-SP1, SUSE Linux Enterprise Server for SAP Applications 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP3, SUSE Linux Enterprise Server for SAP Applications 12-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"dovecot22", rpm:"dovecot22~2.2.31~19.14.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot22-backend-mysql", rpm:"dovecot22-backend-mysql~2.2.31~19.14.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot22-backend-pgsql", rpm:"dovecot22-backend-pgsql~2.2.31~19.14.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot22-backend-sqlite", rpm:"dovecot22-backend-sqlite~2.2.31~19.14.2", rls:"SLES12.0"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"dovecot22", rpm:"dovecot22~2.2.31~19.14.2", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot22-backend-mysql", rpm:"dovecot22-backend-mysql~2.2.31~19.14.2", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot22-backend-pgsql", rpm:"dovecot22-backend-pgsql~2.2.31~19.14.2", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot22-backend-sqlite", rpm:"dovecot22-backend-sqlite~2.2.31~19.14.2", rls:"SLES12.0SP1"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"dovecot22", rpm:"dovecot22~2.2.31~19.14.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot22-backend-mysql", rpm:"dovecot22-backend-mysql~2.2.31~19.14.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot22-backend-pgsql", rpm:"dovecot22-backend-pgsql~2.2.31~19.14.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot22-backend-sqlite", rpm:"dovecot22-backend-sqlite~2.2.31~19.14.2", rls:"SLES12.0SP2"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"dovecot22", rpm:"dovecot22~2.2.31~19.14.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot22-backend-mysql", rpm:"dovecot22-backend-mysql~2.2.31~19.14.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot22-backend-pgsql", rpm:"dovecot22-backend-pgsql~2.2.31~19.14.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot22-backend-sqlite", rpm:"dovecot22-backend-sqlite~2.2.31~19.14.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"dovecot22", rpm:"dovecot22~2.2.31~19.14.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot22-backend-mysql", rpm:"dovecot22-backend-mysql~2.2.31~19.14.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot22-backend-pgsql", rpm:"dovecot22-backend-pgsql~2.2.31~19.14.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot22-backend-sqlite", rpm:"dovecot22-backend-sqlite~2.2.31~19.14.2", rls:"SLES12.0SP4"))) {
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
