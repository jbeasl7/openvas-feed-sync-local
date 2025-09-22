# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.02765.1");
  script_cve_id("CVE-2024-44192", "CVE-2024-54467", "CVE-2025-24189", "CVE-2025-24201", "CVE-2025-31273", "CVE-2025-31278", "CVE-2025-43211", "CVE-2025-43212", "CVE-2025-43216", "CVE-2025-43227", "CVE-2025-43228", "CVE-2025-43240", "CVE-2025-43265", "CVE-2025-6558");
  script_tag(name:"creation_date", value:"2025-08-14 04:12:02 +0000 (Thu, 14 Aug 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-03-14 20:35:27 +0000 (Fri, 14 Mar 2025)");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:02765-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:02765-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202502765-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247562");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247563");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247564");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247595");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247596");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247597");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247598");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247599");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247600");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247742");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-August/041178.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'webkit2gtk3' package(s) announced via the SUSE-SU-2025:02765-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for webkit2gtk3 fixes the following issues:

Updated to version 2.48.5:
 - CVE-2025-31273: Fixed a vulnerability where processing maliciously crafted web content could lead to memory corruption. (bsc#1247564)
 - CVE-2025-31278: Fixed a vulnerability where processing maliciously crafted web content may lead to memory corruption. (bsc#1247563)
 - CVE-2025-43211: Fixed a vulnerability where processing web content may lead to a denial-of-service. (bsc#1247562)
 - CVE-2025-43212: Fixed a vulnerability where processing maliciously crafted web content may lead to an unexpected Safari crash. (bsc#1247595)
 - CVE-2025-43216: Fixed a vulnerability where processing maliciously crafted web content may lead to an unexpected Safari crash. (bsc#1247596)
 - CVE-2025-43227: Fixed a vulnerability where processing maliciously crafted web content may disclose sensitive user information. (bsc#1247597)
 - CVE-2025-43228: Fixed a vulnerability where visiting a malicious website may lead to address bar spoofing. (bsc#1247598)
 - CVE-2025-43240: Fixed a vulnerability where a download's origin may be incorrectly associated. (bsc#1247599)
 - CVE-2025-43265: Fixed a vulnerability where processing maliciously crafted web content may disclose internal states of the app. (bsc#1247600)
 - CVE-2025-6558: Fixed a vulnerability where processing maliciously crafted web content may lead to an unexpected Safari crash. (bsc#1247742)

Other fixes:
- Improve emoji font selection with USE_SKIA=ON.
- Improve playback of multimedia streams from blob URLs.
- Fix the build with USE_SKIA_OPENTYPE_SVG=ON and
 USE_SYSPROF_CAPTURE=ON.
- Fix crash when using a WebKitWebView widget in an offscreen
 window.
- Fix several crashes and rendering issues.
- Fix a crash introduced by the new threaded rendering
 implementation using Skia API.
- Improve rendering performance by recording layers once and
 replaying every dirty region in different worker threads.
- Fix a crash when setting WEBKIT_SKIA_GPU_PAINTING_THREADS=0.
- Fix a reference cycle in webkitmediastreamsrc preventing its
 disposal.
- Increase mem_per_process again to avoid running out of memory.");

  script_tag(name:"affected", value:"'webkit2gtk3' package(s) on openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"WebKitGTK-4.0-lang", rpm:"WebKitGTK-4.0-lang~2.48.5~150600.12.43.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"WebKitGTK-4.1-lang", rpm:"WebKitGTK-4.1-lang~2.48.5~150600.12.43.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"WebKitGTK-6.0-lang", rpm:"WebKitGTK-6.0-lang~2.48.5~150600.12.43.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4_0-18", rpm:"libjavascriptcoregtk-4_0-18~2.48.5~150600.12.43.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4_0-18-32bit", rpm:"libjavascriptcoregtk-4_0-18-32bit~2.48.5~150600.12.43.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4_1-0", rpm:"libjavascriptcoregtk-4_1-0~2.48.5~150600.12.43.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4_1-0-32bit", rpm:"libjavascriptcoregtk-4_1-0-32bit~2.48.5~150600.12.43.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-6_0-1", rpm:"libjavascriptcoregtk-6_0-1~2.48.5~150600.12.43.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4_0-37", rpm:"libwebkit2gtk-4_0-37~2.48.5~150600.12.43.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4_0-37-32bit", rpm:"libwebkit2gtk-4_0-37-32bit~2.48.5~150600.12.43.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4_1-0", rpm:"libwebkit2gtk-4_1-0~2.48.5~150600.12.43.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4_1-0-32bit", rpm:"libwebkit2gtk-4_1-0-32bit~2.48.5~150600.12.43.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkitgtk-6_0-4", rpm:"libwebkitgtk-6_0-4~2.48.5~150600.12.43.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-JavaScriptCore-4_0", rpm:"typelib-1_0-JavaScriptCore-4_0~2.48.5~150600.12.43.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-JavaScriptCore-4_1", rpm:"typelib-1_0-JavaScriptCore-4_1~2.48.5~150600.12.43.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-JavaScriptCore-6_0", rpm:"typelib-1_0-JavaScriptCore-6_0~2.48.5~150600.12.43.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-WebKit-6_0", rpm:"typelib-1_0-WebKit-6_0~2.48.5~150600.12.43.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-WebKit2-4_0", rpm:"typelib-1_0-WebKit2-4_0~2.48.5~150600.12.43.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-WebKit2-4_1", rpm:"typelib-1_0-WebKit2-4_1~2.48.5~150600.12.43.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-WebKit2WebExtension-4_0", rpm:"typelib-1_0-WebKit2WebExtension-4_0~2.48.5~150600.12.43.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-WebKit2WebExtension-4_1", rpm:"typelib-1_0-WebKit2WebExtension-4_1~2.48.5~150600.12.43.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-WebKitWebProcessExtension-6_0", rpm:"typelib-1_0-WebKitWebProcessExtension-6_0~2.48.5~150600.12.43.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit-jsc-4", rpm:"webkit-jsc-4~2.48.5~150600.12.43.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit-jsc-4.1", rpm:"webkit-jsc-4.1~2.48.5~150600.12.43.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit-jsc-6.0", rpm:"webkit-jsc-6.0~2.48.5~150600.12.43.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk-4_0-injected-bundles", rpm:"webkit2gtk-4_0-injected-bundles~2.48.5~150600.12.43.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk-4_1-injected-bundles", rpm:"webkit2gtk-4_1-injected-bundles~2.48.5~150600.12.43.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-devel", rpm:"webkit2gtk3-devel~2.48.5~150600.12.43.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-minibrowser", rpm:"webkit2gtk3-minibrowser~2.48.5~150600.12.43.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-soup2-devel", rpm:"webkit2gtk3-soup2-devel~2.48.5~150600.12.43.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-soup2-minibrowser", rpm:"webkit2gtk3-soup2-minibrowser~2.48.5~150600.12.43.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk4-devel", rpm:"webkit2gtk4-devel~2.48.5~150600.12.43.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk4-minibrowser", rpm:"webkit2gtk4-minibrowser~2.48.5~150600.12.43.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkitgtk-6_0-injected-bundles", rpm:"webkitgtk-6_0-injected-bundles~2.48.5~150600.12.43.1", rls:"openSUSELeap15.6"))) {
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
