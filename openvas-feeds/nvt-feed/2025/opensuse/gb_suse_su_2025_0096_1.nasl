# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856921");
  script_version("2025-02-20T08:47:14+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2024-40866", "CVE-2024-44185", "CVE-2024-44187", "CVE-2024-44308", "CVE-2024-44309", "CVE-2024-54479", "CVE-2024-54502", "CVE-2024-54505", "CVE-2024-54508", "CVE-2024-54534");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-20 08:47:14 +0000 (Thu, 20 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-13 17:42:04 +0000 (Fri, 13 Dec 2024)");
  script_tag(name:"creation_date", value:"2025-01-15 05:00:44 +0000 (Wed, 15 Jan 2025)");
  script_name("openSUSE: Security Advisory for webkit2gtk3 (SUSE-SU-2025:0096-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.4");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:0096-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/VNOWYQ4XFQ5ZUWJVRGOT6AZPTHMA3T6A");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'webkit2gtk3'
  package(s) announced via the SUSE-SU-2025:0096-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for webkit2gtk3 fixes the following issues:

  Update to version 2.46.5 (bsc#1234851):

  Security fixes:

  * CVE-2024-54479: Processing maliciously crafted web content may lead to an
      unexpected process crash

  * CVE-2024-54502: Processing maliciously crafted web content may lead to an
      unexpected process crash

  * CVE-2024-54505: Processing maliciously crafted web content may lead to
      memory corruption

  * CVE-2024-54508: Processing maliciously crafted web content may lead to an
      unexpected process crash

  * CVE-2024-54534: Processing maliciously crafted web content may lead to
      memory corruption

  Other fixes:

  * Fix the build with GBM and release logs disabled.

  * Fix several crashes and rendering issues.

  * Improve memory consumption and performance of Canvas getImageData.

  * Fix preserve-3D intersection rendering.

  * Fix video dimensions since GStreamer 1.24.9.

  * Fix the HTTP-based remote Web Inspector not loading in Chromium.

  * Fix content filters not working on about:blank iframes.

  * Fix several crashes and rendering issues.");

  script_tag(name:"affected", value:"'webkit2gtk3' package(s) on openSUSE Leap 15.4.");

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

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"WebKitGTK", rpm:"WebKitGTK~4.0~lang~2.46.5~150400.4.103.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkitgtk-60-injected-bundles", rpm:"webkitgtk-60-injected-bundles~2.46.5~150400.4.103.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkitgtk-60-4", rpm:"libwebkitgtk-60-4~2.46.5~150400.4.103.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-soup2-minibrowser-debuginfo", rpm:"webkit2gtk3-soup2-minibrowser-debuginfo~2.46.5~150400.4.103.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-41-0-debuginfo", rpm:"libjavascriptcoregtk-41-0-debuginfo~2.46.5~150400.4.103.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-minibrowser", rpm:"webkit2gtk3-minibrowser~2.46.5~150400.4.103.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-40-37", rpm:"libwebkit2gtk-40-37~2.46.5~150400.4.103.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit-jsc", rpm:"webkit-jsc~4.1~debuginfo~2.46.5~150400.4.103.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-minibrowser-debuginfo", rpm:"webkit2gtk3-minibrowser-debuginfo~2.46.5~150400.4.103.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-40-18", rpm:"libjavascriptcoregtk-40-18~2.46.5~150400.4.103.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-60-1-debuginfo", rpm:"libjavascriptcoregtk-60-1-debuginfo~2.46.5~150400.4.103.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-soup2-minibrowser", rpm:"webkit2gtk3-soup2-minibrowser~2.46.5~150400.4.103.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-debugsource", rpm:"webkit2gtk3-debugsource~2.46.5~150400.4.103.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-soup2-devel", rpm:"webkit2gtk3-soup2-devel~2.46.5~150400.4.103.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk4-devel", rpm:"webkit2gtk4-devel~2.46.5~150400.4.103.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkitgtk-60-4-debuginfo", rpm:"libwebkitgtk-60-4-debuginfo~2.46.5~150400.4.103.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-41-0-debuginfo", rpm:"libwebkit2gtk-41-0-debuginfo~2.46.5~150400.4.103.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-10-WebKit2-41", rpm:"typelib-10-WebKit2-41~2.46.5~150400.4.103.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-10-WebKit2-40", rpm:"typelib-10-WebKit2-40~2.46.5~150400.4.103.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-10-JavaScriptCore-40", rpm:"typelib-10-JavaScriptCore-40~2.46.5~150400.4.103.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-60-1", rpm:"libjavascriptcoregtk-60-1~2.46.5~150400.4.103.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk-40-injected-bundles", rpm:"webkit2gtk-40-injected-bundles~2.46.5~150400.4.103.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-10-WebKitWebProcessExtension-60", rpm:"typelib-10-WebKitWebProcessExtension-60~2.46.5~150400.4.103.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit-jsc-4", rpm:"webkit-jsc-4~2.46.5~150400.4.103.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk-40-injected-bundles-debuginfo", rpm:"webkit2gtk-40-injected-bundles-debuginfo~2.46.5~150400.4.103.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-41-0", rpm:"libwebkit2gtk-41-0~2.46.5~150400.4.103.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk-41-injected-bundles", rpm:"webkit2gtk-41-injected-bundles~2.46.5~150400.4.103.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit-jsc", rpm:"webkit-jsc~6.0~2.46.5~150400.4.103.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk-41-injected-bundles-debuginfo", rpm:"webkit2gtk-41-injected-bundles-debuginfo~2.46.5~150400.4.103.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-10-WebKit2WebExtension-41", rpm:"typelib-10-WebKit2WebExtension-41~2.46.5~150400.4.103.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit-jsc", rpm:"webkit-jsc~6.0~debuginfo~2.46.5~150400.4.103.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-devel", rpm:"webkit2gtk3-devel~2.46.5~150400.4.103.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk4-debugsource", rpm:"webkit2gtk4-debugsource~2.46.5~150400.4.103.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-10-JavaScriptCore-41", rpm:"typelib-10-JavaScriptCore-41~2.46.5~150400.4.103.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk4-minibrowser-debuginfo", rpm:"webkit2gtk4-minibrowser-debuginfo~2.46.5~150400.4.103.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk4-minibrowser", rpm:"webkit2gtk4-minibrowser~2.46.5~150400.4.103.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-10-WebKit-60", rpm:"typelib-10-WebKit-60~2.46.5~150400.4.103.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkitgtk-60-injected-bundles-debuginfo", rpm:"webkitgtk-60-injected-bundles-debuginfo~2.46.5~150400.4.103.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-soup2-debugsource", rpm:"webkit2gtk3-soup2-debugsource~2.46.5~150400.4.103.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-40-37-debuginfo", rpm:"libwebkit2gtk-40-37-debuginfo~2.46.5~150400.4.103.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit-jsc-4-debuginfo", rpm:"webkit-jsc-4-debuginfo~2.46.5~150400.4.103.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit-jsc", rpm:"webkit-jsc~4.1~2.46.5~150400.4.103.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-10-WebKit2WebExtension-40", rpm:"typelib-10-WebKit2WebExtension-40~2.46.5~150400.4.103.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-41-0", rpm:"libjavascriptcoregtk-41-0~2.46.5~150400.4.103.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-10-JavaScriptCore-60", rpm:"typelib-10-JavaScriptCore-60~2.46.5~150400.4.103.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-40-18-debuginfo", rpm:"libjavascriptcoregtk-40-18-debuginfo~2.46.5~150400.4.103.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-41-0-32bit", rpm:"libjavascriptcoregtk-41-0-32bit~2.46.5~150400.4.103.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-41-0-32bit-debuginfo", rpm:"libwebkit2gtk-41-0-32bit-debuginfo~2.46.5~150400.4.103.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-40-37-32bit", rpm:"libwebkit2gtk-40-37-32bit~2.46.5~150400.4.103.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-40-37-32bit-debuginfo", rpm:"libwebkit2gtk-40-37-32bit-debuginfo~2.46.5~150400.4.103.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-40-18-32bit", rpm:"libjavascriptcoregtk-40-18-32bit~2.46.5~150400.4.103.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-40-18-32bit-debuginfo", rpm:"libjavascriptcoregtk-40-18-32bit-debuginfo~2.46.5~150400.4.103.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-41-0-32bit", rpm:"libwebkit2gtk-41-0-32bit~2.46.5~150400.4.103.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-41-0-32bit-debuginfo", rpm:"libjavascriptcoregtk-41-0-32bit-debuginfo~2.46.5~150400.4.103.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-40-37-64bit", rpm:"libwebkit2gtk-40-37-64bit~2.46.5~150400.4.103.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-41-0-64bit-debuginfo", rpm:"libjavascriptcoregtk-41-0-64bit-debuginfo~2.46.5~150400.4.103.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-41-0-64bit-debuginfo", rpm:"libwebkit2gtk-41-0-64bit-debuginfo~2.46.5~150400.4.103.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-40-18-64bit", rpm:"libjavascriptcoregtk-40-18-64bit~2.46.5~150400.4.103.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-40-18-64bit-debuginfo", rpm:"libjavascriptcoregtk-40-18-64bit-debuginfo~2.46.5~150400.4.103.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-41-0-64bit", rpm:"libwebkit2gtk-41-0-64bit~2.46.5~150400.4.103.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-41-0-64bit", rpm:"libjavascriptcoregtk-41-0-64bit~2.46.5~150400.4.103.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-40-37-64bit-debuginfo", rpm:"libwebkit2gtk-40-37-64bit-debuginfo~2.46.5~150400.4.103.1", rls:"openSUSELeap15.4"))) {
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
