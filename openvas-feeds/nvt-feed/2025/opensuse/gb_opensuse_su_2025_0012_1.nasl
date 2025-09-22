# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.1.2025.0012.1");
  script_cve_id("CVE-2024-11395");
  script_tag(name:"creation_date", value:"2025-02-18 11:01:57 +0000 (Tue, 18 Feb 2025)");
  script_version("2025-02-20T08:47:14+0000");
  script_tag(name:"last_modification", value:"2025-02-20 08:47:14 +0000 (Thu, 20 Feb 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (openSUSE-SU-2025:0012-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2025:0012-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/Q3PEGRWS7VSTXHREFS3ULWWCUPH6HWX2/");
  script_xref(name:"URL", value:"https://blogs.opera.com/desktop/changelog-for-116");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'opera' package(s) announced via the openSUSE-SU-2025:0012-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for opera fixes the following issues:

- Update to 116.0.5366.21
 * CHR-9904 Update Chromium on desktop-stable-131-5366 to
 131.0.6778.86
 * DNA-119581 Crash at views::View::ConvertPointToTarget
 * DNA-119847 Missing Opera warning color and some margins
 in Settings
 * DNA-119853 Eula dialog is wrong displayed and can not run
 installation with system scale 125%
 * DNA-119883 Dark mode: side bar player icons have
 no background
 * DNA-120054 Double icon effect in adress bar
 * DNA-120117 [Player] Crash when trying to Inspect Element
 on player's web page in panel
 * DNA-120155 Crash on opera:extensions with color-themes
 flag disabled
 * DNA-120195 Scroll in Theme Gallery view changes to dark
 color in Dark Mode
 * DNA-120211 Crash at extensions::
 TabsPrivateGetAllInWindowFunction::Run
 * DNA-120230 Start page button is blurry
 * DNA-120240 Dropdown display lacks expected overlay effect
 * DNA-120242 Translations for Opera 116
 * DNA-120317 Crash at opera::BrowserWindowImpl::
 SetBrowserUIVisible
 * DNA-120458 Crash at opera::BrowserWindowImpl::
 AddWidgetToTracked
 * DNA-120512 Promote 116.0 to stable
- Complete Opera 116 changelog at:
 [link moved to references]
- The update to chromium 131.0.6778.86 fixes following issues:
 CVE-2024-11395


- Update to 115.0.5322.119
 * CHR-9416 Updating Chromium on desktop-stable-* branches
 * DNA-120117 [Player] Crash when trying to Inspect Element on
 player's web page in panel
 * DNA-120211 Crash at extensions::
 TabsPrivateGetAllInWindowFunction::Run

- Update to 115.0.5322.109
 * CHR-9416 Updating Chromium on desktop-stable-* branches
 * DNA-118730 Crash at opera::content_filter::
 AdBlockerWhitelistHandler::SetSiteBlocked
 * DNA-119320 [Mac] Web view corners not rounded
 * DNA-119421 [Easy setup] Dropdown for theme editing do not
 close after opening other dropdowns
 * DNA-119519 Implement stop mechanism for video as wallpaper
 * DNA-119550 Collect common shader rendering code in
 Rich Wallpaper
 * DNA-119551 Convert Midsommar to new shader-based dynamic
 theme format
 * DNA-119552 Convert Aurora to new shader-based dynamic
 theme format
 * DNA-119553 Pass configuration data to shader-based
 dynamic themes
 * DNA-119554 Logic for pause / resume animations in rich
 wallpaper page
 * DNA-119645 Install theme from the server
 * DNA-119652 Show spinner while downloading & installing theme
 * DNA-119692 'start now' button not translated in hindi
 * DNA-119783 Toggles in Dark Mode unchecked state missed
 background color
 * DNA-119811 Show download icon on hover
 * DNA-119812 Implement downloading new theme by clicking
 download button
 * DNA-119813 Implement selecting new theme by clicking tile
 * DNA-119814 Implement canceling theme download API
 * DNA-119815 Implement canceling theme download UI
 * DNA-119816 Handle error callback from download/install
 * DNA-119817 Implement ability to see themes being downloaded
 ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'opera' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"opera", rpm:"opera~116.0.5366.21~lp156.2.26.1", rls:"openSUSELeap15.6"))) {
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
