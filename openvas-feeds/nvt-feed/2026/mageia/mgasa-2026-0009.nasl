# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2026.0009");
  script_cve_id("CVE-2025-55130", "CVE-2025-55131", "CVE-2025-55132", "CVE-2025-59465", "CVE-2025-59466", "CVE-2026-21637");
  script_tag(name:"creation_date", value:"2026-01-19 04:28:26 +0000 (Mon, 19 Jan 2026)");
  script_version("2026-01-19T05:50:51+0000");
  script_tag(name:"last_modification", value:"2026-01-19 05:50:51 +0000 (Mon, 19 Jan 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2026-0009)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2026-0009");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2026-0009.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=34995");
  script_xref(name:"URL", value:"https://nodejs.org/en/blog/release/v22.22.0");
  script_xref(name:"URL", value:"https://nodejs.org/en/blog/vulnerability/december-2025-security-releases");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nodejs' package(s) announced via the MGASA-2026-0009 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Node.js HTTP/2 server crashes with unhandled error when receiving
malformed HEADERS frame. (CVE-2025-59465)
Uncatchable 'Maximum call stack size exceeded' error on Node.js via
async_hooks leads to process crashes bypassing error handlers.
(CVE-2025-59466)
Bypass File System Permissions using crafted symlinks. (CVE-2025-55130)
Timeout-based race conditions make Uint8Array/Buffer.alloc
non-zerofilled. (CVE-2025-55131)
fs.futimes() Bypasses Read-Only Permission Model. (CVE-2025-55132)
TLS PSK/ALPN Callback Exceptions Bypass Error Handlers, Causing DoS and
FD Leak. (CVE-2026-21637)");

  script_tag(name:"affected", value:"'nodejs' package(s) on Mageia 9.");

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

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"nodejs", rpm:"nodejs~22.22.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs-devel", rpm:"nodejs-devel~22.22.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs-docs", rpm:"nodejs-docs~22.22.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs-libs", rpm:"nodejs-libs~22.22.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"npm", rpm:"npm~10.9.4~1.22.22.0.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"v8-devel", rpm:"v8-devel~12.4.254.21.mga9~6.mga9", rls:"MAGEIA9"))) {
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
