# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.20122.1");
  script_cve_id("CVE-2025-61726", "CVE-2025-61728", "CVE-2025-61730", "CVE-2025-61731", "CVE-2025-68119", "CVE-2025-68121");
  script_tag(name:"creation_date", value:"2026-01-30 04:34:32 +0000 (Fri, 30 Jan 2026)");
  script_version("2026-01-30T05:55:24+0000");
  script_tag(name:"last_modification", value:"2026-01-30 05:55:24 +0000 (Fri, 30 Jan 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:20122-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES16\.0\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:20122-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-202620122-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236217");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256816");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256817");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256818");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256819");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256820");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256821");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2026-January/043748.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'go1.24' package(s) announced via the SUSE-SU-2026:20122-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- CVE-2025-61730: crypto/tls: handshake messages may be processed at the incorrect encryption level (bsc#1256821).
 - CVE-2025-68119: cmd/go: unexpected code execution when invoking toolchain (bsc#1256820).
 - CVE-2025-61731: cmd/go: bypass of flag sanitization can lead to arbitrary code execution (bsc#1256819).
 - CVE-2025-61726: net/http: memory exhaustion in Request.ParseForm (bsc#1256817).
 - CVE-2025-61728: archive/zip: denial of service when parsing arbitrary ZIP archives (bsc#1256816).
 - CVE-2025-68121: crypto/tls: Config.Clone copies automatically generated session ticket keys, session resumption does not account for the expiration of full certificate chain (bsc#1256818).

Other fixes:

 * go#76408 crypto/tls: earlyTrafficSecret should use ClientHelloInner if ECH enabled
 * go#76624 os: on Unix, Readdirnames skips directory entries with zero inodes
 * go#76760 runtime: stack split at bad time in os/signal with Go 1.25.4 windows 386
 * go#76796 runtime: race detector crash on ppc64le
 * go#76966 cmd/compile/internal/ssa: Compile.func1(): panic during sccp while compiling &lt,function&gt,: runtime error: index out of range");

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

  if(!isnull(res = isrpmvuln(pkg:"go1.24", rpm:"go1.24~1.24.12~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.24-doc", rpm:"go1.24-doc~1.24.12~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.24-libstd", rpm:"go1.24-libstd~1.24.12~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.24-race", rpm:"go1.24-race~1.24.12~160000.1.1", rls:"SLES16.0.0"))) {
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
