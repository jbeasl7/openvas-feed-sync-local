# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.2618.1");
  script_cve_id("CVE-2022-30550");
  script_tag(name:"creation_date", value:"2022-08-02 04:46:45 +0000 (Tue, 02 Aug 2022)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-25 23:48:55 +0000 (Mon, 25 Jul 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:2618-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2|SLES12\.0SP3|SLES12\.0SP4|SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2618-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20222618-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1201267");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2022-August/011732.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dovecot22' package(s) announced via the SUSE-SU-2022:2618-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for dovecot22 fixes the following issues:

- CVE-2022-30550: Fixed privilege escalation in dovecot when similar master and non-master passdbs are used (bsc#1201267).");

  script_tag(name:"affected", value:"'dovecot22' package(s) on SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP4, SUSE Linux Enterprise Server for SAP Applications 12-SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"dovecot22", rpm:"dovecot22~2.2.31~19.29.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot22-backend-mysql", rpm:"dovecot22-backend-mysql~2.2.31~19.29.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot22-backend-pgsql", rpm:"dovecot22-backend-pgsql~2.2.31~19.29.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot22-backend-sqlite", rpm:"dovecot22-backend-sqlite~2.2.31~19.29.1", rls:"SLES12.0SP2"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"dovecot22", rpm:"dovecot22~2.2.31~19.29.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot22-backend-mysql", rpm:"dovecot22-backend-mysql~2.2.31~19.29.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot22-backend-pgsql", rpm:"dovecot22-backend-pgsql~2.2.31~19.29.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot22-backend-sqlite", rpm:"dovecot22-backend-sqlite~2.2.31~19.29.1", rls:"SLES12.0SP3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"dovecot22", rpm:"dovecot22~2.2.31~19.29.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot22-backend-mysql", rpm:"dovecot22-backend-mysql~2.2.31~19.29.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot22-backend-pgsql", rpm:"dovecot22-backend-pgsql~2.2.31~19.29.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot22-backend-sqlite", rpm:"dovecot22-backend-sqlite~2.2.31~19.29.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"dovecot22", rpm:"dovecot22~2.2.31~19.29.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot22-backend-mysql", rpm:"dovecot22-backend-mysql~2.2.31~19.29.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot22-backend-pgsql", rpm:"dovecot22-backend-pgsql~2.2.31~19.29.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot22-backend-sqlite", rpm:"dovecot22-backend-sqlite~2.2.31~19.29.1", rls:"SLES12.0SP5"))) {
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
