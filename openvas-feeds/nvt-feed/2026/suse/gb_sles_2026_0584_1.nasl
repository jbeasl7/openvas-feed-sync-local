# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.0584.1");
  script_cve_id("CVE-2026-2003", "CVE-2026-2004", "CVE-2026-2005", "CVE-2026-2006", "CVE-2026-2007");
  script_tag(name:"creation_date", value:"2026-02-23 04:43:33 +0000 (Mon, 23 Feb 2026)");
  script_version("2026-02-23T06:01:22+0000");
  script_tag(name:"last_modification", value:"2026-02-23 06:01:22 +0000 (Mon, 23 Feb 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:0584-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4|SLES15\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:0584-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20260584-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258008");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258009");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258010");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258011");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258012");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-February/024362.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql18' package(s) announced via the SUSE-SU-2026:0584-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for postgresql18 fixes the following issues:

Update to version 18.2.

Security issues fixed:

- CVE-2026-2003: improper validation of type 'oidvector' may allow disclose a few bytes of server memory (bsc#1258008).
- CVE-2026-2004: intarray missing validation of type of input to selectivity estimator could lead to arbitrary code
 execution (bsc#1258009).
- CVE-2026-2005: buffer overrun in contrib/pgcrypto's PGP decryption functions could lead to arbitrary code execution
 (bsc#1258010).
- CVE-2026-2006: inadequate validation of multibyte character lengths could lead to arbitrary code execution
 (bsc#1258011).
- CVE-2026-2007: pg_trgm heap buffer overflow can cause to write pattern onto server memory (bsc#1258012).");

  script_tag(name:"affected", value:"'postgresql18' package(s) on SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server 15-SP5, SUSE Linux Enterprise Server for SAP Applications 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP5.");

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

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"libecpg6", rpm:"libecpg6~18.2~150200.5.6.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpq5", rpm:"libpq5~18.2~150200.5.6.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpq5-32bit", rpm:"libpq5-32bit~18.2~150200.5.6.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"libecpg6", rpm:"libecpg6~18.2~150200.5.6.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpq5", rpm:"libpq5~18.2~150200.5.6.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpq5-32bit", rpm:"libpq5-32bit~18.2~150200.5.6.1", rls:"SLES15.0SP5"))) {
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
