# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.20587.1");
  script_cve_id("CVE-2025-12817", "CVE-2025-12818", "CVE-2026-2003", "CVE-2026-2004", "CVE-2026-2005", "CVE-2026-2006");
  script_tag(name:"creation_date", value:"2026-03-09 04:38:35 +0000 (Mon, 09 Mar 2026)");
  script_version("2026-03-10T10:15:11+0000");
  script_tag(name:"last_modification", value:"2026-03-10 10:15:11 +0000 (Tue, 10 Mar 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:20587-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES16\.0\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:20587-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-202620587-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253332");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253333");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258008");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258009");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258010");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258011");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-March/024619.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql14' package(s) announced via the SUSE-SU-2026:20587-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for postgresql14 fixes the following issues:

Update to version 14.21.

Security issues fixed:

- CVE-2026-2003: improper validation of type 'oidvector' may allow disclose a few bytes of server memory (bsc#1258008).
- CVE-2026-2004: intarray missing validation of type of input to selectivity estimator could lead to arbitrary code
 execution (bsc#1258009).
- CVE-2026-2005: buffer overrun in contrib/pgcrypto's PGP decryption functions could lead to arbitrary code execution
 (bsc#1258010).
- CVE-2026-2006: inadequate validation of multibyte character lengths could lead to arbitrary code execution
 (bsc#1258011).
- CVE-2025-12817: missing check for CREATE privileges on the schema in CREATE STATISTICS (bsc#1253332).
- CVE-2025-12818: integer overflow in allocation-size calculations within libpq (bsc#1253333).");

  script_tag(name:"affected", value:"'postgresql14' package(s) on SUSE Linux Enterprise Server 16.0, SUSE Linux Enterprise Server for SAP Applications 16.0.");

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

  if(!isnull(res = isrpmvuln(pkg:"postgresql14", rpm:"postgresql14~14.21~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-contrib", rpm:"postgresql14-contrib~14.21~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-devel", rpm:"postgresql14-devel~14.21~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-docs", rpm:"postgresql14-docs~14.21~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-plperl", rpm:"postgresql14-plperl~14.21~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-plpython", rpm:"postgresql14-plpython~14.21~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-pltcl", rpm:"postgresql14-pltcl~14.21~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-server", rpm:"postgresql14-server~14.21~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-server-devel", rpm:"postgresql14-server-devel~14.21~160000.1.1", rls:"SLES16.0.0"))) {
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
