# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833694");
  script_version("2025-03-11T05:38:16+0000");
  script_cve_id("CVE-2023-2312", "CVE-2023-3420", "CVE-2023-3421", "CVE-2023-3422", "CVE-2023-4068", "CVE-2023-4069", "CVE-2023-4070", "CVE-2023-4071", "CVE-2023-4072", "CVE-2023-4073", "CVE-2023-4074", "CVE-2023-4075", "CVE-2023-4076", "CVE-2023-4077", "CVE-2023-4078", "CVE-2023-4349", "CVE-2023-4350", "CVE-2023-4351", "CVE-2023-4352", "CVE-2023-4353", "CVE-2023-4354", "CVE-2023-4355", "CVE-2023-4356", "CVE-2023-4357", "CVE-2023-4358", "CVE-2023-4359", "CVE-2023-4360", "CVE-2023-4361", "CVE-2023-4362", "CVE-2023-4363", "CVE-2023-4364", "CVE-2023-4365", "CVE-2023-4366", "CVE-2023-4367", "CVE-2023-4368", "CVE-2023-4572");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-31 18:28:39 +0000 (Thu, 31 Aug 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:55:11 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for opera (openSUSE-SU-2023:0251-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.4:NonFree");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2023:0251-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/OZ42BLWF46DJIINWQUMWAD3MX5OLXGUI");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'opera'
  package(s) announced via the openSUSE-SU-2023:0251-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for opera fixes the following issues:

  - Update to 102.0.4880.40

  * DNA-111203 Prepare translations for home button in settings

  - Changes in 102.0.4880.38

  * DNA-110720 [Sidebar] Sidebar app increase size every time it's reopened

  * DNA-110723 Music logo in light mode of 'Select service' unreadable on
         hover

  * DNA-110821 Run-if-alive callback missing in WMFDecoderImpl

  * DNA-110835 Search/copy popup issues

  * DNA-111038 Disable profile migration

  * DNA-111263 Tab island animation incorrect when tabstrip full

  - Update to 102.0.4880.33

  * CHR-9411 Update Chromium on desktop-stable-116-4880 to 116.0.5845.141

  * DNA-110172 [BUG] Images inside popup does not get rounded corner

  * DNA-110828 Update chess.com build

  * DNA-110834 Crash at opera::component_based::
         TabAnimationController::StartAnimatedLayout(opera::
         component_based::TabAnimationController::AnimationInfo,
         base::OnceCallback)

  * DNA-111144 Enable a new version of the extension.

  - The update to chromium 116.0.5845.141 fixes following issues:
       CVE-2023-4572

  - Update to 102.0.4880.29

  * DNA-109498 Splash screen is shown on every restart of the browser

  * DNA-109698 Test Amazon Music support

  * DNA-109840 Amazon music logo is very small and unreadable

  * DNA-109841 Amazon music logo in player mode is too wide

  * DNA-109842 [opauto] Add tests for Amazon Music in Player

  * DNA-109937 Crash at opera::ComponentTabStripController::
         SetGroupCollapsed(tab_groups::TabGroupId const&amp, bool)

  * DNA-110107 Clicking roblox link on page closes the tab

  * DNA-110110 [Tab strip][Tab island] Middle/right mouse click
         on top of the screen have no/wrong effect

  * DNA-110125 [Win/Lin] New design for default scrollbars on web page

  * DNA-110130 Capture mouse events on the 1-pixel edge to the right of
         the web view

  * DNA-110586 Shadow is clipped if first tab is selected

  * DNA-110637 Revert removal of start page button

  * DNA-110684 Add bookmarks permissions

  * DNA-110702 [Scrollable] Pin group is not aligned with address bar

  * DNA-110737 [OMenu] Menu button looks weird

  * DNA-110788 No 1-pixel edge in full screen mode

  * DNA-110828 Update chess.com build

  * DNA-110842 [Tab strip] Make + button round(er) again

  * DNA-110874 Bring back Home button

  * DNA-110876 Search box on Start page without transparency

  * DNA-110878 Turn on Amazo ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'opera' package(s) on openSUSE Leap 15.4:NonFree.");

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

if(release == "openSUSELeap15.4:NonFree") {

  if(!isnull(res = isrpmvuln(pkg:"opera", rpm:"opera~102.0.4880.40~lp154.2.50.1", rls:"openSUSELeap15.4:NonFree"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opera", rpm:"opera~102.0.4880.40~lp154.2.50.1", rls:"openSUSELeap15.4:NonFree"))) {
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