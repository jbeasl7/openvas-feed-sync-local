# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2026.0070");
  script_cve_id("CVE-2026-33416", "CVE-2026-33636");
  script_tag(name:"creation_date", value:"2026-03-30 05:00:13 +0000 (Mon, 30 Mar 2026)");
  script_version("2026-03-30T06:15:36+0000");
  script_tag(name:"last_modification", value:"2026-03-30 06:15:36 +0000 (Mon, 30 Mar 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2026-0070)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2026-0070");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2026-0070.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=35279");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2026/03/26/1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libpng' package(s) announced via the MGASA-2026-0070 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Use-after-free via pointer aliasing in png_set_tRNS and png_set_PLTE.
(CVE-2026-33416)
Out-of-bounds read/write in the palette expansion on ARM Neon.
(CVE-2026-33636)");

  script_tag(name:"affected", value:"'libpng' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64png-devel", rpm:"lib64png-devel~1.6.38~1.5.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64png16_16", rpm:"lib64png16_16~1.6.38~1.5.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng", rpm:"libpng~1.6.38~1.5.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng-devel", rpm:"libpng-devel~1.6.38~1.5.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng16_16", rpm:"libpng16_16~1.6.38~1.5.mga9", rls:"MAGEIA9"))) {
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
