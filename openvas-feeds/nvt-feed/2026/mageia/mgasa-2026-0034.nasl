# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2026.0034");
  script_cve_id("CVE-2025-15269", "CVE-2025-15270", "CVE-2025-15275", "CVE-2025-15279");
  script_tag(name:"creation_date", value:"2026-02-10 04:48:24 +0000 (Tue, 10 Feb 2026)");
  script_version("2026-02-10T08:18:30+0000");
  script_tag(name:"last_modification", value:"2026-02-10 08:18:30 +0000 (Tue, 10 Feb 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2026-0034)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2026-0034");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2026-0034.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=35091");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-hp8x-4h95-9799");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/NFM3OPUTYR55GA65K3XOPK3FXAH7EWEJ/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'fontforge' package(s) announced via the MGASA-2026-0034 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"FontForge SFD File Parsing Use-After-Free Remote Code Execution
Vulnerability. (CVE-2025-15269)
FontForge SFD File Parsing Improper Validation of Array Index Remote
Code Execution Vulnerability. (CVE-2025-15270)
FontForge SFD File Parsing Heap-based Buffer Overflow Remote Code
Execution Vulnerability. (CVE-2025-15275)
FontForge GUtils BMP File Parsing Heap-based Buffer Overflow Remote Code
Execution Vulnerability. (CVE-2025-15279)");

  script_tag(name:"affected", value:"'fontforge' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"fontforge", rpm:"fontforge~20220308~2.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fontforge-doc", rpm:"fontforge-doc~20220308~2.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64fontforge4", rpm:"lib64fontforge4~20220308~2.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfontforge4", rpm:"libfontforge4~20220308~2.2.mga9", rls:"MAGEIA9"))) {
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
