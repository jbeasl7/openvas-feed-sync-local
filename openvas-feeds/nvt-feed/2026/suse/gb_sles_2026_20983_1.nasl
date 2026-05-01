# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.20983.1");
  script_cve_id("CVE-2026-2003", "CVE-2026-2004", "CVE-2026-2005", "CVE-2026-2006");
  script_tag(name:"creation_date", value:"2026-04-13 05:04:44 +0000 (Mon, 13 Apr 2026)");
  script_version("2026-04-13T06:24:05+0000");
  script_tag(name:"last_modification", value:"2026-04-13 06:24:05 +0000 (Mon, 13 Apr 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:20983-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES16\.0\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:20983-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-202620983-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258008");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258009");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258010");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258011");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258754");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2026-April/045348.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql16' package(s) announced via the SUSE-SU-2026:20983-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for postgresql16 fixes the following issues:

- Update to versio 16.13. (bsc#1258754)
- CVE-2026-2003: Guard against unexpected dimensions of oidvector/int2vector (bsc#1258008)
- CVE-2026-2004: Harden selectivity estimators against being attached to operators that accept unexpected data types. (bsc#1258009)
- CVE-2026-2005: Fix buffer overrun in contrib/pgcrypto's PGP decryption functions. (bsc#1258010)
- CVE-2026-2006: Fix inadequate validation of multibyte character lengths. (bsc#1258011)");

  script_tag(name:"affected", value:"'postgresql16' package(s) on SUSE Linux Enterprise Server 16.0, SUSE Linux Enterprise Server for SAP Applications 16.0.");

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

if(release == "SLES16.0.0") {

  if(!isnull(res = isrpmvuln(pkg:"postgresql16", rpm:"postgresql16~16.13~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-contrib", rpm:"postgresql16-contrib~16.13~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-devel", rpm:"postgresql16-devel~16.13~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-docs", rpm:"postgresql16-docs~16.13~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-plperl", rpm:"postgresql16-plperl~16.13~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-plpython", rpm:"postgresql16-plpython~16.13~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-pltcl", rpm:"postgresql16-pltcl~16.13~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-server", rpm:"postgresql16-server~16.13~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-server-devel", rpm:"postgresql16-server-devel~16.13~160000.1.1", rls:"SLES16.0.0"))) {
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
