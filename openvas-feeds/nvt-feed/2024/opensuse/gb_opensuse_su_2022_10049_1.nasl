# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833004");
  script_version("2025-03-11T05:38:16+0000");
  script_cve_id("CVE-2022-0797", "CVE-2022-1125", "CVE-2022-1138", "CVE-2022-1305", "CVE-2022-1310", "CVE-2022-1314", "CVE-2022-1493");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-28 14:43:53 +0000 (Thu, 28 Jul 2022)");
  script_tag(name:"creation_date", value:"2024-03-04 07:34:33 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for libqt5 (openSUSE-SU-2022:10049-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSEBackportsSLE-15-SP4");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2022:10049-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/WT2AEVSRASQUW7I7AGAMZLKVP3GE3BMY");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libqt5'
  package(s) announced via the openSUSE-SU-2022:10049-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libqt5-qtwebengine fixes the following issues:
  Update to version 5.15.10:

  * Fix top level build with no widget

  * Fix read-after-free on EGL extensions

  * Update Chromium

  * Add workaround for unstable gn on macOS in ci

  * Pass archiver to gn build

  * Fix navigation to non-local URLs

  * Add support for universal builds for qtwebengine and qtpdf

  * Enable Apple Silicon support

  * Fix cross compilation x86_64- arm64 on mac

  * Bump version to 5.15.10

  * CustomDialogs: Make custom input fields readable in dark mode

  * CookieBrowser: Make alternating rows readable in dark mode

  * Update Chromium:

  * Bump V8_PATCH_LEVEL

  * Fix clang set-but-unused-variable warning

  * Fix mac toolchain python linker script call

  * Fix missing dependency for gpu sources

  * Fix python calls

  * Fix undefined symbol for universal link

  * Quick fix for regression in service workers by reverting backports

  * [Backport] CVE-2022-0797: Out of bounds memory access in Mojo

  * [Backport] CVE-2022-1125

  * [Backport] CVE-2022-1138: Inappropriate implementation in Web Cursor.

  * [Backport] CVE-2022-1305: Use after free in storage

  * [Backport] CVE-2022-1310: Use after free in regular expressions

  * [Backport] CVE-2022-1314: Type Confusion in V8

  * [Backport] CVE-2022-1493: Use after free in Dev Tools

  * [Backport] On arm64 hosts, set host_cpu to 'arm64', not 'arm'

  * [Backport] Security Bug 1296876

  * [Backport] Security bug 1269999

  * [Backport] Security bug 1280852

  * [Backport] Security bug 1292905

  * [Backport] Security bug 1304659

  * [Backport] Security bug 1306507");

  script_tag(name:"affected", value:"'libqt5' package(s) on openSUSE Backports SLE-15-SP4.");

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

if(release == "openSUSEBackportsSLE-15-SP4") {

  if(!isnull(res = isrpmvuln(pkg:"libQt5Pdf5", rpm:"libQt5Pdf5~5.15.10~bp154.2.3.2", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5PdfWidgets5", rpm:"libQt5PdfWidgets5~5.15.10~bp154.2.3.2", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtpdf-devel", rpm:"libqt5-qtpdf-devel~5.15.10~bp154.2.3.2", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtpdf-examples", rpm:"libqt5-qtpdf-examples~5.15.10~bp154.2.3.2", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtpdf-imports", rpm:"libqt5-qtpdf-imports~5.15.10~bp154.2.3.2", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtwebengine", rpm:"libqt5-qtwebengine~5.15.10~bp154.2.3.2", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtwebengine-devel", rpm:"libqt5-qtwebengine-devel~5.15.10~bp154.2.3.2", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtwebengine-examples", rpm:"libqt5-qtwebengine-examples~5.15.10~bp154.2.3.2", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtpdf-private-headers-devel", rpm:"libqt5-qtpdf-private-headers-devel~5.15.10~bp154.2.3.2", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtwebengine-private-headers-devel", rpm:"libqt5-qtwebengine-private-headers-devel~5.15.10~bp154.2.3.2", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Pdf5", rpm:"libQt5Pdf5~5.15.10~bp154.2.3.2", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5PdfWidgets5", rpm:"libQt5PdfWidgets5~5.15.10~bp154.2.3.2", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtpdf-devel", rpm:"libqt5-qtpdf-devel~5.15.10~bp154.2.3.2", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtpdf-examples", rpm:"libqt5-qtpdf-examples~5.15.10~bp154.2.3.2", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtpdf-imports", rpm:"libqt5-qtpdf-imports~5.15.10~bp154.2.3.2", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtwebengine", rpm:"libqt5-qtwebengine~5.15.10~bp154.2.3.2", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtwebengine-devel", rpm:"libqt5-qtwebengine-devel~5.15.10~bp154.2.3.2", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtwebengine-examples", rpm:"libqt5-qtwebengine-examples~5.15.10~bp154.2.3.2", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtpdf-private-headers-devel", rpm:"libqt5-qtpdf-private-headers-devel~5.15.10~bp154.2.3.2", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtwebengine-private-headers-devel", rpm:"libqt5-qtwebengine-private-headers-devel~5.15.10~bp154.2.3.2", rls:"openSUSEBackportsSLE-15-SP4"))) {
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