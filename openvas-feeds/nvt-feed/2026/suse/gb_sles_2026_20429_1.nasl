# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.20429.1");
  script_cve_id("CVE-2025-61732", "CVE-2025-68119", "CVE-2025-68121");
  script_tag(name:"creation_date", value:"2026-02-20 04:36:11 +0000 (Fri, 20 Feb 2026)");
  script_version("2026-02-20T05:55:45+0000");
  script_tag(name:"last_modification", value:"2026-02-20 05:55:45 +0000 (Fri, 20 Feb 2026)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-02-10 16:08:03 +0000 (Tue, 10 Feb 2026)");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:20429-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES16\.0\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:20429-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-202620429-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236217");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256818");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256820");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257692");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-February/024343.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'go1.24' package(s) announced via the SUSE-SU-2026:20429-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for go1.24 fixes the following issues:

Update to version 1.24.13.

Security issues fixed:

- CVE-2025-61732: cmd/go: discrepancy between Go and C/C++ comment parsing allows for C code smuggling (bsc#1257692).
- CVE-2025-68121: crypto/tls: Config.Clone copies automatically generated session ticket keys, session resumption does
 not account for the expiration of full certificate chain (bsc#1256818).
- CVE-2025-68119: cmd/go: unexpected code execution when invoking toolchain (bsc1256820).

Other updates and bugfixes:

- version update to 1.24.13:

 * go#77323 crypto/x509: single-label excluded DNS name constraints incorrectly match all wildcard SANs
 * go#77424 crypto/tls: CL 737700 broke session resumption on macOS");

  script_tag(name:"affected", value:"'go1.24' package(s) on SUSE Linux Enterprise Server 16.0, SUSE Linux Enterprise Server for SAP Applications 16.0.");

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

  if(!isnull(res = isrpmvuln(pkg:"go1.24", rpm:"go1.24~1.24.13~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.24-doc", rpm:"go1.24-doc~1.24.13~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.24-libstd", rpm:"go1.24-libstd~1.24.13~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.24-race", rpm:"go1.24-race~1.24.13~160000.1.1", rls:"SLES16.0.0"))) {
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
