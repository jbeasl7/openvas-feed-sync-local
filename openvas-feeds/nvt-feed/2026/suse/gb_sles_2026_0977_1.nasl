# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.0977.1");
  script_cve_id("CVE-2025-61732", "CVE-2025-68121", "CVE-2026-25679", "CVE-2026-27139", "CVE-2026-27142");
  script_tag(name:"creation_date", value:"2026-03-26 04:49:18 +0000 (Thu, 26 Mar 2026)");
  script_version("2026-03-26T06:06:30+0000");
  script_tag(name:"last_modification", value:"2026-03-26 06:06:30 +0000 (Thu, 26 Mar 2026)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-02-10 16:08:03 +0000 (Tue, 10 Feb 2026)");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:0977-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP6)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:0977-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20260977-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244485");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256818");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257692");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1259264");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1259265");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1259268");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-March/024820.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'go1.25-openssl' package(s) announced via the SUSE-SU-2026:0977-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for go1.25-openssl fixes the following issues:

Update to go 1.25.8 (bsc#1244485, jsc#SLE-18320):

- CVE-2025-61732: cmd/cgo: discrepancy between Go and C/C++ comment parsing allows for C code smuggling (bsc#1257692).
- CVE-2025-68121: crypto/tls: Config.Clone copies automatically generated session ticket keys, session resumption does
 not account for the expiration of full certificate chain (bsc#1256818).
- CVE-2026-25679: net/url: reject IPv6 literal not at start of host (bsc#1259264).
- CVE-2026-27139: os: FileInfo can escape from a Root (bsc#1259268).
- CVE-2026-27142: html/template: URLs in meta content attribute actions are not escaped (bsc#1259265).

Changelog:

 * go#77253 cmd/compile: miscompile of global array initialization
 * go#77406 os: Go 1.25.x regression on RemoveAll for windows
 * go#77413 runtime: netpollinit() incorrectly prints the error from linux.Eventfd
 * go#77438 cmd/go: CGO compilation fails after upgrading from Go 1.25.5 to 1.25.6 due to --define-variable flag in
 pkg-config
 * go#77531 net/smtp: expiry date of localhostCert for testing is too short
 * go#75844 cmd/compile: OOM killed on linux/arm64
 * go#77323 crypto/x509: single-label excluded DNS name constraints incorrectly match all wildcard SANs
 * go#77425 crypto/tls: CL 737700 broke session resumption on macOS");

  script_tag(name:"affected", value:"'go1.25-openssl' package(s) on SUSE Linux Enterprise Server 15-SP6, SUSE Linux Enterprise Server for SAP Applications 15-SP6.");

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

if(release == "SLES15.0SP6") {

  if(!isnull(res = isrpmvuln(pkg:"go1.25-openssl", rpm:"go1.25-openssl~1.25.8~150600.13.15.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.25-openssl-doc", rpm:"go1.25-openssl-doc~1.25.8~150600.13.15.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.25-openssl-race", rpm:"go1.25-openssl-race~1.25.8~150600.13.15.1", rls:"SLES15.0SP6"))) {
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
