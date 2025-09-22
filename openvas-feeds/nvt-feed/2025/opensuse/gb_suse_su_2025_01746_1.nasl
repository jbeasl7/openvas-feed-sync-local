# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.01746.1");
  script_cve_id("CVE-2023-42875", "CVE-2023-42970", "CVE-2024-23226", "CVE-2025-24223", "CVE-2025-31204", "CVE-2025-31205", "CVE-2025-31206", "CVE-2025-31215", "CVE-2025-31257");
  script_tag(name:"creation_date", value:"2025-06-02 04:12:38 +0000 (Mon, 02 Jun 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-05 16:33:06 +0000 (Thu, 05 Dec 2024)");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:01746-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:01746-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202501746-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222905");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241158");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241160");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243282");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243286");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243288");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243289");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243424");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243596");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-May/039422.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'webkit2gtk3' package(s) announced via the SUSE-SU-2025:01746-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for webkit2gtk3 fixes the following issues:

Update to version 2.48.2.

Security issues fixed:

- CVE-2025-31205: lack of checks may lead to cross-origin data exfiltration through a malicious website (bsc#1243282).
- CVE-2025-31204: improper memory handling when processing certain web content may lead to memory corruption
 (bsc#1243286).
- CVE-2025-31206: type confusion issue when processing certain web content may lead to an unexpected crash
 (bsc#1243288).
- CVE-2025-31215: lack of checks when processing certain web content may lead to an unexpected crash (bsc#1243289).
- CVE-2025-31257: improper memory handling when processing certain web content may lead to an unexpected crash
 (bsc#1243596).
- CVE-2025-24223: improper memory handling when processing certain web content may lead to memory corruption
 (bsc#1243424).

Other changes and issues fixed:

- Enable CSS overscroll behavior by default.
- Change threaded rendering implementation to use Skia API instead of WebCore display list that is not thread safe.
- Fix rendering when device scale factor change comes before the web view geometry update.
- Fix network process crash on exit.
- Fix the build with ENABLE_RESOURCE_USAGE=OFF.
- Fix several crashes and rendering issues.");

  script_tag(name:"affected", value:"'webkit2gtk3' package(s) on openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"WebKitGTK-4.0-lang", rpm:"WebKitGTK-4.0-lang~2.48.2~150600.12.40.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"WebKitGTK-4.1-lang", rpm:"WebKitGTK-4.1-lang~2.48.2~150600.12.40.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"WebKitGTK-6.0-lang", rpm:"WebKitGTK-6.0-lang~2.48.2~150600.12.40.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4_0-18", rpm:"libjavascriptcoregtk-4_0-18~2.48.2~150600.12.40.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4_0-18-32bit", rpm:"libjavascriptcoregtk-4_0-18-32bit~2.48.2~150600.12.40.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4_1-0", rpm:"libjavascriptcoregtk-4_1-0~2.48.2~150600.12.40.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4_1-0-32bit", rpm:"libjavascriptcoregtk-4_1-0-32bit~2.48.2~150600.12.40.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-6_0-1", rpm:"libjavascriptcoregtk-6_0-1~2.48.2~150600.12.40.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4_0-37", rpm:"libwebkit2gtk-4_0-37~2.48.2~150600.12.40.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4_0-37-32bit", rpm:"libwebkit2gtk-4_0-37-32bit~2.48.2~150600.12.40.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4_1-0", rpm:"libwebkit2gtk-4_1-0~2.48.2~150600.12.40.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4_1-0-32bit", rpm:"libwebkit2gtk-4_1-0-32bit~2.48.2~150600.12.40.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkitgtk-6_0-4", rpm:"libwebkitgtk-6_0-4~2.48.2~150600.12.40.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-JavaScriptCore-4_0", rpm:"typelib-1_0-JavaScriptCore-4_0~2.48.2~150600.12.40.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-JavaScriptCore-4_1", rpm:"typelib-1_0-JavaScriptCore-4_1~2.48.2~150600.12.40.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-JavaScriptCore-6_0", rpm:"typelib-1_0-JavaScriptCore-6_0~2.48.2~150600.12.40.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-WebKit-6_0", rpm:"typelib-1_0-WebKit-6_0~2.48.2~150600.12.40.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-WebKit2-4_0", rpm:"typelib-1_0-WebKit2-4_0~2.48.2~150600.12.40.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-WebKit2-4_1", rpm:"typelib-1_0-WebKit2-4_1~2.48.2~150600.12.40.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-WebKit2WebExtension-4_0", rpm:"typelib-1_0-WebKit2WebExtension-4_0~2.48.2~150600.12.40.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-WebKit2WebExtension-4_1", rpm:"typelib-1_0-WebKit2WebExtension-4_1~2.48.2~150600.12.40.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-WebKitWebProcessExtension-6_0", rpm:"typelib-1_0-WebKitWebProcessExtension-6_0~2.48.2~150600.12.40.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit-jsc-4", rpm:"webkit-jsc-4~2.48.2~150600.12.40.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit-jsc-4.1", rpm:"webkit-jsc-4.1~2.48.2~150600.12.40.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit-jsc-6.0", rpm:"webkit-jsc-6.0~2.48.2~150600.12.40.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk-4_0-injected-bundles", rpm:"webkit2gtk-4_0-injected-bundles~2.48.2~150600.12.40.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk-4_1-injected-bundles", rpm:"webkit2gtk-4_1-injected-bundles~2.48.2~150600.12.40.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-devel", rpm:"webkit2gtk3-devel~2.48.2~150600.12.40.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-minibrowser", rpm:"webkit2gtk3-minibrowser~2.48.2~150600.12.40.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-soup2-devel", rpm:"webkit2gtk3-soup2-devel~2.48.2~150600.12.40.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-soup2-minibrowser", rpm:"webkit2gtk3-soup2-minibrowser~2.48.2~150600.12.40.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk4-devel", rpm:"webkit2gtk4-devel~2.48.2~150600.12.40.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk4-minibrowser", rpm:"webkit2gtk4-minibrowser~2.48.2~150600.12.40.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkitgtk-6_0-injected-bundles", rpm:"webkitgtk-6_0-injected-bundles~2.48.2~150600.12.40.2", rls:"openSUSELeap15.6"))) {
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
