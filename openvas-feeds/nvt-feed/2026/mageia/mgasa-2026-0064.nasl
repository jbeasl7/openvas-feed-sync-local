# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2026.0064");
  script_cve_id("CVE-2025-43457", "CVE-2026-20608", "CVE-2026-20635", "CVE-2026-20636", "CVE-2026-20644", "CVE-2026-20652", "CVE-2026-20676");
  script_tag(name:"creation_date", value:"2026-03-25 04:42:47 +0000 (Wed, 25 Mar 2026)");
  script_version("2026-03-25T05:58:02+0000");
  script_tag(name:"last_modification", value:"2026-03-25 05:58:02 +0000 (Wed, 25 Mar 2026)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-02-13 14:46:38 +0000 (Fri, 13 Feb 2026)");

  script_name("Mageia: Security Advisory (MGASA-2026-0064)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2026-0064");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2026-0064.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=35228");
  script_xref(name:"URL", value:"https://webkitgtk.org/2026/03/12/webkitgtk2.50.6-released.html");
  script_xref(name:"URL", value:"https://webkitgtk.org/security/WSA-2026-0001.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'webkit2' package(s) announced via the MGASA-2026-0064 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2025-43457 Processing maliciously crafted web content may lead to an
unexpected Safari crash. A use-after-free issue was addressed with improved
memory management.
CVE-2026-20608 Processing maliciously crafted web content may lead to an
unexpected process crash. This issue was addressed through improved state
management.
CVE-2026-20635 Processing maliciously crafted web content may lead to an
unexpected process crash. The issue was addressed with improved memory
handling.
CVE-2026-20636 Processing maliciously crafted web content may lead to an
unexpected process crash. The issue was addressed with improved memory
handling.
CVE-2026-20644 Processing maliciously crafted web content may lead to an
unexpected process crash. The issue was addressed with improved memory
handling.
CVE-2026-20652 A remote attacker may be able to cause a denial-of-service.
The issue was addressed with improved memory handling.
CVE-2026-20676 A website may be able to track users through Safari web
extensions. This issue was addressed through improved state management.");

  script_tag(name:"affected", value:"'webkit2' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64javascriptcore-gir4.0", rpm:"lib64javascriptcore-gir4.0~2.50.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64javascriptcore-gir4.1", rpm:"lib64javascriptcore-gir4.1~2.50.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64javascriptcore-gir6.0", rpm:"lib64javascriptcore-gir6.0~2.50.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64javascriptcoregtk4.0_18", rpm:"lib64javascriptcoregtk4.0_18~2.50.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64javascriptcoregtk4.1_0", rpm:"lib64javascriptcoregtk4.1_0~2.50.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64javascriptcoregtk6.0_1", rpm:"lib64javascriptcoregtk6.0_1~2.50.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64webkit2gtk-gir4.0", rpm:"lib64webkit2gtk-gir4.0~2.50.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64webkit2gtk-gir4.1", rpm:"lib64webkit2gtk-gir4.1~2.50.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64webkit2gtk4.0-devel", rpm:"lib64webkit2gtk4.0-devel~2.50.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64webkit2gtk4.0_37", rpm:"lib64webkit2gtk4.0_37~2.50.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64webkit2gtk4.1-devel", rpm:"lib64webkit2gtk4.1-devel~2.50.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64webkit2gtk4.1_0", rpm:"lib64webkit2gtk4.1_0~2.50.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64webkitgtk-gir6.0", rpm:"lib64webkitgtk-gir6.0~2.50.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64webkitgtk6.0-devel", rpm:"lib64webkitgtk6.0-devel~2.50.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64webkitgtk6.0_4", rpm:"lib64webkitgtk6.0_4~2.50.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcore-gir4.0", rpm:"libjavascriptcore-gir4.0~2.50.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcore-gir4.1", rpm:"libjavascriptcore-gir4.1~2.50.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcore-gir6.0", rpm:"libjavascriptcore-gir6.0~2.50.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk4.0_18", rpm:"libjavascriptcoregtk4.0_18~2.50.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk4.1_0", rpm:"libjavascriptcoregtk4.1_0~2.50.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk6.0_1", rpm:"libjavascriptcoregtk6.0_1~2.50.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-gir4.0", rpm:"libwebkit2gtk-gir4.0~2.50.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-gir4.1", rpm:"libwebkit2gtk-gir4.1~2.50.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk4.0-devel", rpm:"libwebkit2gtk4.0-devel~2.50.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk4.0_37", rpm:"libwebkit2gtk4.0_37~2.50.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk4.1-devel", rpm:"libwebkit2gtk4.1-devel~2.50.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk4.1_0", rpm:"libwebkit2gtk4.1_0~2.50.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkitgtk-gir6.0", rpm:"libwebkitgtk-gir6.0~2.50.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkitgtk6.0-devel", rpm:"libwebkitgtk6.0-devel~2.50.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkitgtk6.0_4", rpm:"libwebkitgtk6.0_4~2.50.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2", rpm:"webkit2~2.50.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2-driver", rpm:"webkit2-driver~2.50.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk4.0", rpm:"webkit2gtk4.0~2.50.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk4.0-jsc", rpm:"webkit2gtk4.0-jsc~2.50.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk4.1", rpm:"webkit2gtk4.1~2.50.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk4.1-jsc", rpm:"webkit2gtk4.1-jsc~2.50.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkitgtk6.0", rpm:"webkitgtk6.0~2.50.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkitgtk6.0-jsc", rpm:"webkitgtk6.0-jsc~2.50.6~1.mga9", rls:"MAGEIA9"))) {
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
