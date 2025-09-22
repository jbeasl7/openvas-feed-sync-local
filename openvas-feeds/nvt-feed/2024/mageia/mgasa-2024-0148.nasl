# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0148");
  script_cve_id("CVE-2014-1745", "CVE-2023-37450", "CVE-2023-38133", "CVE-2023-38572", "CVE-2023-38592", "CVE-2023-38594", "CVE-2023-38595", "CVE-2023-38597", "CVE-2023-38599", "CVE-2023-38600", "CVE-2023-38611", "CVE-2023-39434", "CVE-2023-39928", "CVE-2023-40397", "CVE-2023-40414", "CVE-2023-40451", "CVE-2023-41074", "CVE-2023-41993", "CVE-2023-42843", "CVE-2023-42883", "CVE-2023-42890", "CVE-2023-42916", "CVE-2023-42917", "CVE-2023-42950", "CVE-2023-42956", "CVE-2024-23206", "CVE-2024-23213", "CVE-2024-23222", "CVE-2024-23252", "CVE-2024-23254", "CVE-2024-23263", "CVE-2024-23280", "CVE-2024-23284");
  script_tag(name:"creation_date", value:"2024-04-29 04:12:50 +0000 (Mon, 29 Apr 2024)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-18 14:30:39 +0000 (Thu, 18 Jan 2024)");

  script_name("Mageia: Security Advisory (MGASA-2024-0148)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0148");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0148.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32202");
  script_xref(name:"URL", value:"https://webkitgtk.org/2023/07/04/webkitgtk2.41.6-released.html");
  script_xref(name:"URL", value:"https://webkitgtk.org/2023/07/21/webkitgtk2.40.4-released.html");
  script_xref(name:"URL", value:"https://webkitgtk.org/2023/08/01/webkitgtk2.40.5-released.html");
  script_xref(name:"URL", value:"https://webkitgtk.org/2023/08/10/webkitgtk2.41.90-released.html");
  script_xref(name:"URL", value:"https://webkitgtk.org/2023/08/19/webkitgtk2.41.91-released.html");
  script_xref(name:"URL", value:"https://webkitgtk.org/2023/09/08/webkitgtk2.41.92-released.html");
  script_xref(name:"URL", value:"https://webkitgtk.org/2023/09/15/webkitgtk2.42.0-released.html");
  script_xref(name:"URL", value:"https://webkitgtk.org/2023/11/10/webkitgtk2.42.2-released.html");
  script_xref(name:"URL", value:"https://webkitgtk.org/2023/11/17/webkitgtk2.43.1-released.html");
  script_xref(name:"URL", value:"https://webkitgtk.org/2023/12/05/webkitgtk2.42.3-released.html");
  script_xref(name:"URL", value:"https://webkitgtk.org/2023/12/15/webkitgtk2.42.4-released.html");
  script_xref(name:"URL", value:"https://webkitgtk.org/2023/12/21/webkitgtk2.43.3-released.html");
  script_xref(name:"URL", value:"https://webkitgtk.org/2024/02/02/webkitgtk2.43.4-released.html");
  script_xref(name:"URL", value:"https://webkitgtk.org/2024/02/05/webkitgtk2.42.5-released.html");
  script_xref(name:"URL", value:"https://webkitgtk.org/2024/03/16/webkitgtk2.44.0-released.html");
  script_xref(name:"URL", value:"https://webkitgtk.org/2024/04/09/webkitgtk2.44.1-released.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'webkit2' package(s) announced via the MGASA-2024-0148 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Due to issues in our build system this package is very outdated, now
that the issues are fixed we are publishing the current upstream
version.
Lot of CVEs are fixed and a lot of changes were made by upstream, see
the links.");

  script_tag(name:"affected", value:"'webkit2' package(s) on Mageia 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64javascriptcore-gir4.0", rpm:"lib64javascriptcore-gir4.0~2.44.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64javascriptcore-gir4.1", rpm:"lib64javascriptcore-gir4.1~2.44.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64javascriptcore-gir6.0", rpm:"lib64javascriptcore-gir6.0~2.44.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64javascriptcoregtk4.0_18", rpm:"lib64javascriptcoregtk4.0_18~2.44.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64javascriptcoregtk4.1_0", rpm:"lib64javascriptcoregtk4.1_0~2.44.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64javascriptcoregtk6.0_1", rpm:"lib64javascriptcoregtk6.0_1~2.44.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64webkit2gtk-gir4.0", rpm:"lib64webkit2gtk-gir4.0~2.44.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64webkit2gtk-gir4.1", rpm:"lib64webkit2gtk-gir4.1~2.44.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64webkit2gtk4.0-devel", rpm:"lib64webkit2gtk4.0-devel~2.44.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64webkit2gtk4.0_37", rpm:"lib64webkit2gtk4.0_37~2.44.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64webkit2gtk4.1-devel", rpm:"lib64webkit2gtk4.1-devel~2.44.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64webkit2gtk4.1_0", rpm:"lib64webkit2gtk4.1_0~2.44.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64webkitgtk-gir6.0", rpm:"lib64webkitgtk-gir6.0~2.44.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64webkitgtk6.0-devel", rpm:"lib64webkitgtk6.0-devel~2.44.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64webkitgtk6.0_4", rpm:"lib64webkitgtk6.0_4~2.44.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcore-gir4.0", rpm:"libjavascriptcore-gir4.0~2.44.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcore-gir4.1", rpm:"libjavascriptcore-gir4.1~2.44.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcore-gir6.0", rpm:"libjavascriptcore-gir6.0~2.44.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk4.0_18", rpm:"libjavascriptcoregtk4.0_18~2.44.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk4.1_0", rpm:"libjavascriptcoregtk4.1_0~2.44.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk6.0_1", rpm:"libjavascriptcoregtk6.0_1~2.44.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-gir4.0", rpm:"libwebkit2gtk-gir4.0~2.44.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-gir4.1", rpm:"libwebkit2gtk-gir4.1~2.44.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk4.0-devel", rpm:"libwebkit2gtk4.0-devel~2.44.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk4.0_37", rpm:"libwebkit2gtk4.0_37~2.44.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk4.1-devel", rpm:"libwebkit2gtk4.1-devel~2.44.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk4.1_0", rpm:"libwebkit2gtk4.1_0~2.44.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkitgtk-gir6.0", rpm:"libwebkitgtk-gir6.0~2.44.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkitgtk6.0-devel", rpm:"libwebkitgtk6.0-devel~2.44.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkitgtk6.0_4", rpm:"libwebkitgtk6.0_4~2.44.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2", rpm:"webkit2~2.44.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2-driver", rpm:"webkit2-driver~2.44.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk4.0", rpm:"webkit2gtk4.0~2.44.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk4.0-jsc", rpm:"webkit2gtk4.0-jsc~2.44.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk4.1", rpm:"webkit2gtk4.1~2.44.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk4.1-jsc", rpm:"webkit2gtk4.1-jsc~2.44.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkitgtk6.0", rpm:"webkitgtk6.0~2.44.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkitgtk6.0-jsc", rpm:"webkitgtk6.0-jsc~2.44.1~1.mga9", rls:"MAGEIA9"))) {
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
