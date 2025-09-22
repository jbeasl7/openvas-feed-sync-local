# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.2958.1");
  script_cve_id("CVE-2021-23214", "CVE-2021-23222", "CVE-2021-32027", "CVE-2021-32028", "CVE-2021-32029", "CVE-2021-3677", "CVE-2022-1552", "CVE-2022-2625");
  script_tag(name:"creation_date", value:"2022-09-01 04:49:22 +0000 (Thu, 01 Sep 2022)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-07 20:04:33 +0000 (Wed, 07 Sep 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:2958-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2958-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20222958-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179945");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1183168");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185924");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185925");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185926");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185952");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1187751");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189748");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190740");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1192516");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1195680");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1198166");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1199475");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1202368");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2022-August/012016.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql12' package(s) announced via the SUSE-SU-2022:2958-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for postgresql12 fixes the following issues:

- Upgrade to 12.12:
- CVE-2022-2625: Fixed an issue where extension scripts would replace objects not belonging to that extension (bsc#1202368).

- Upgrade to 12.11:
- CVE-2022-1552: Confined additional operations within 'security restricted operation' sandboxes (bsc#1199475).

- Upgrade to 12.10 (bsc#1195680)
- Add constraints file with 12GB of memory for s390x as a workaround (boo#1190740)

- Upgrade to version 12.9 (bsc#1192516):
- CVE-2021-23214: Made the server reject extraneous data after an SSL or GSS encryption handshake
- CVE-2021-23222: Made libpq reject extraneous data after an SSL or GSS encryption handshake

- Upgrade to version 12.8:
- CVE-2021-3677: Fixed memory disclosure in certain queries (bsc#1189748).

- Upgrade to version 12.7:
- CVE-2021-32027: Fixed integer overflows in array subscripting calculations (bsc#1185924).
- CVE-2021-32028: Fixed mishandling of junk columns in INSERT ... ON CONFLICT ... UPDATE target lists (bsc#1185925).
- CVE-2021-32029: Fixed possibly-incorrect computation of UPDATE ... RETURNING 'pg_psql_temporary_savepoint' does not exist (bsc#1185926).

- Fixed build with llvm12 on s390x (bsc#1185952).
- Re-enabled icu for PostgreSQL 10 (bsc#1179945).
- Made the dependency of postgresqlXX-server-devel on llvm and clang optional (bsc#1187751).
- llvm12 breaks PostgreSQL 11 and 12 on s390x. Use llvm11 as a workaround (bsc#1185952).
- Don't use %_stop_on_removal, because it was meant to be private and got removed from openSUSE. %_restart_on_update is also private, but still supported and needed for now (bsc#1183168).");

  script_tag(name:"affected", value:"'postgresql12' package(s) on SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server for SAP Applications 15-SP1.");

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

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"libecpg6", rpm:"libecpg6~12.12~150100.3.33.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpq5", rpm:"libpq5~12.12~150100.3.33.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpq5-32bit", rpm:"libpq5-32bit~12.12~150100.3.33.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql12", rpm:"postgresql12~12.12~150100.3.33.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql12-contrib", rpm:"postgresql12-contrib~12.12~150100.3.33.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql12-devel", rpm:"postgresql12-devel~12.12~150100.3.33.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql12-docs", rpm:"postgresql12-docs~12.12~150100.3.33.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql12-plperl", rpm:"postgresql12-plperl~12.12~150100.3.33.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql12-plpython", rpm:"postgresql12-plpython~12.12~150100.3.33.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql12-pltcl", rpm:"postgresql12-pltcl~12.12~150100.3.33.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql12-server", rpm:"postgresql12-server~12.12~150100.3.33.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql12-server-devel", rpm:"postgresql12-server-devel~12.12~150100.3.33.1", rls:"SLES15.0SP1"))) {
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
