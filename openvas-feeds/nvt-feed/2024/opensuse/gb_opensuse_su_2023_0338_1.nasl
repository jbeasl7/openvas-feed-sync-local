# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833219");
  script_version("2025-03-11T05:38:16+0000");
  script_cve_id("CVE-2023-5218", "CVE-2023-5473", "CVE-2023-5474", "CVE-2023-5475", "CVE-2023-5476", "CVE-2023-5477", "CVE-2023-5478", "CVE-2023-5479", "CVE-2023-5481", "CVE-2023-5483", "CVE-2023-5484", "CVE-2023-5485", "CVE-2023-5486", "CVE-2023-5487");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-12 15:50:51 +0000 (Thu, 12 Oct 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:14:37 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for opera (openSUSE-SU-2023:0338-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5:NonFree");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2023:0338-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/CBGGDMAKEIS7OWQIGRX4OQWPP7OTHLDW");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'opera'
  package(s) announced via the openSUSE-SU-2023:0338-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for opera fixes the following issues:

  - Update to 104.0.4944.23

  * DNA-110465 [Scrollable tab strip] Weird animation when closing tab

  * DNA-112021 Favicons disappear from history after being hovered over

  * DNA-112310 Put opening animation on start page behind a flag

  * DNA-112462 Crash at opera::SidebarItemViewImpl::
         StateChanged(views::Button::ButtonState)

  * DNA-112464 Crash at anonymous namespace::SwitchToTabButton::
         OnThemeChanged()

  * DNA-112518 Force Default as last used Profile

  * DNA-112534 Set profiles_order to Default dir

  - Changes in 104.0.4944.18

  * CHR-9471 Update Chromium on desktop-stable-118-4944 to 118.0.5993.71

  * DNA-111704 chrome.webRequest.onHeadersReceived event is not fired for
         extension if page opened from SpeedDial tile

  * DNA-111878 Highlighting of tabs and bookmarks in dark mode is almost
         invisible.

  * DNA-111883 [Address bar] Hover effect on page is placed too high

  * DNA-111922 [Linux] Change Opera beta application icon

  * DNA-111955 Reduce colors used in Opera as much as possible

  * DNA-112075 Rename palette colors in theme for better reusability

  * DNA-112108 Fix dangling WebContents ptr bound to
         TabSnoozeInfobarDelegate::Show callback

  * DNA-112222 Tab in island not marked as active

  * DNA-112242 Disable feature flag #platform-h264-decoder-in-gpu by
         default on stable channel

  * DNA-112265 Promote 104 to stable

  * DNA-112312 Turn on #wallet-selector on all streams

  * DNA-112313 Enable #pinboard-popup-refresh on all streams

  * DNA-112426 [profile migration] Renaming invalid Default to Default.old
         is not needed anymore

  - The update to chromium 118.0.5993.71 fixes following issues:
       CVE-2023-5218, CVE-2023-5487, CVE-2023-5484, CVE-2023-5475,
       CVE-2023-5483, CVE-2023-5481, CVE-2023-5476, CVE-2023-5474,
       CVE-2023-5479, CVE-2023-5485, CVE-2023-5478, CVE-2023-5477,
       CVE-2023-5486, CVE-2023-5473

  - Update to 103.0.4928.34

  * DNA-111680 Fix highlight of bookmarks bar folder elements

  * DNA-111703 O icon moves upon opening menu

  * DNA-111883 [Address bar] Hover effect on page is placed too high

  * DNA-111940 OMenu text displaced to the right without any indentation

  * DNA-112118 Crash at history::URLDatabase::
         CreateContinueOnIndexIfNeeded(std::__Cr::vector)

  - Update to 103.0.4928.26

  * DNA-111681 Disappearing icons of bookmarks bar folders elements

  * DNA-112020 Enable #address-bar-dropdown-cities on all streams");

  script_tag(name:"affected", value:"'opera' package(s) on openSUSE Leap 15.5:NonFree.");

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

if(release == "openSUSELeap15.5:NonFree") {

  if(!isnull(res = isrpmvuln(pkg:"opera", rpm:"opera~104.0.4944.23~lp155.3.15.1", rls:"openSUSELeap15.5:NonFree"))) {
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
