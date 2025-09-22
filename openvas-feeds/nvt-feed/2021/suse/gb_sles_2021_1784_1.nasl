# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.1784.1");
  script_cve_id("CVE-2021-32027", "CVE-2021-32028", "CVE-2021-32029");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:37 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-10 13:54:44 +0000 (Thu, 10 Jun 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:1784-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:1784-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20211784-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179945");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1183118");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1183168");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185924");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185925");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185926");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2021-May/008873.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql13' package(s) announced via the SUSE-SU-2021:1784-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for postgresql13 fixes the following issues:

- Upgrade to version 13.3:
- CVE-2021-32027: Fixed integer overflows in array subscripting calculations (bsc#1185924).
- CVE-2021-32028: Fixed mishandling of junk columns in INSERT ... ON CONFLICT ... UPDATE target lists (bsc#1185925).
- CVE-2021-32029: Fixed possibly-incorrect computation of UPDATE ... RETURNING 'pg_psql_temporary_savepoint' does not exist (bsc#1185926).

- Don't use %_stop_on_removal, because it was meant to be private and got removed from openSUSE. %_restart_on_update is also private, but still supported and needed for now (bsc#1183168).
- Re-enable build of the llvmjit subpackage on SLE, but it will only be delivered on PackageHub for now (bsc#1183118).
- Disable icu for PostgreSQL 10 (and older) on TW (bsc#1179945).");

  script_tag(name:"affected", value:"'postgresql13' package(s) on SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"libecpg6", rpm:"libecpg6~13.3~3.9.3", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpq5", rpm:"libpq5~13.3~3.9.3", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpq5-32bit", rpm:"libpq5-32bit~13.3~3.9.3", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql13", rpm:"postgresql13~13.3~3.9.3", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql13-contrib", rpm:"postgresql13-contrib~13.3~3.9.3", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql13-docs", rpm:"postgresql13-docs~13.3~3.9.3", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql13-plperl", rpm:"postgresql13-plperl~13.3~3.9.3", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql13-plpython", rpm:"postgresql13-plpython~13.3~3.9.3", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql13-pltcl", rpm:"postgresql13-pltcl~13.3~3.9.3", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql13-server", rpm:"postgresql13-server~13.3~3.9.3", rls:"SLES12.0SP5"))) {
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
