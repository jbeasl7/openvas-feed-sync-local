# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.3153.1");
  script_cve_id("CVE-2024-7348");
  script_tag(name:"creation_date", value:"2024-09-09 04:27:00 +0000 (Mon, 09 Sep 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-12 15:54:52 +0000 (Mon, 12 Aug 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:3153-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2|SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3153-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20243153-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229013");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2024-September/036810.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql16' package(s) announced via the SUSE-SU-2024:3153-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for postgresql16 fixes the following issues:

- Upgrade to 12.20 (bsc#1229013)
- CVE-2024-7348: PostgreSQL relation replacement during pg_dump executes arbitrary SQL. (bsc#1229013)");

  script_tag(name:"affected", value:"'postgresql16' package(s) on SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP2, SUSE Linux Enterprise Server for SAP Applications 15-SP3.");

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

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"postgresql12", rpm:"postgresql12~12.20~150200.8.63.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql12-contrib", rpm:"postgresql12-contrib~12.20~150200.8.63.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql12-devel", rpm:"postgresql12-devel~12.20~150200.8.63.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql12-docs", rpm:"postgresql12-docs~12.20~150200.8.63.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql12-plperl", rpm:"postgresql12-plperl~12.20~150200.8.63.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql12-plpython", rpm:"postgresql12-plpython~12.20~150200.8.63.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql12-pltcl", rpm:"postgresql12-pltcl~12.20~150200.8.63.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql12-server", rpm:"postgresql12-server~12.20~150200.8.63.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql12-server-devel", rpm:"postgresql12-server-devel~12.20~150200.8.63.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"postgresql12", rpm:"postgresql12~12.20~150200.8.63.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql12-contrib", rpm:"postgresql12-contrib~12.20~150200.8.63.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql12-devel", rpm:"postgresql12-devel~12.20~150200.8.63.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql12-docs", rpm:"postgresql12-docs~12.20~150200.8.63.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql12-plperl", rpm:"postgresql12-plperl~12.20~150200.8.63.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql12-plpython", rpm:"postgresql12-plpython~12.20~150200.8.63.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql12-pltcl", rpm:"postgresql12-pltcl~12.20~150200.8.63.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql12-server", rpm:"postgresql12-server~12.20~150200.8.63.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql12-server-devel", rpm:"postgresql12-server-devel~12.20~150200.8.63.1", rls:"SLES15.0SP3"))) {
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
