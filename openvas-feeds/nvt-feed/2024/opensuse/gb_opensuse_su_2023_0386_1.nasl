# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833045");
  script_version("2025-03-11T05:38:16+0000");
  script_cve_id("CVE-2023-5997", "CVE-2023-6112");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-21 01:01:21 +0000 (Tue, 21 Nov 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:57:39 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for opera (openSUSE-SU-2023:0386-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5:NonFree");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2023:0386-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/TS7DENNWXUXU3ROQQDHEYSOBWA6FR367");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'opera'
  package(s) announced via the openSUSE-SU-2023:0386-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for opera fixes the following issues:

  - Update to 105.0.4970.21

  * DNA-112425 Choosing Workspace Icons does not work as expected

  * DNA-112787 glow around tiles in Top Sites section in BABE in dark theme

  - The update to chromium 119.0.6045.159 fixes following issues:
       CVE-2023-5997, CVE-2023-6112

  - Update to 105.0.4970.16

  * CHR-9416 Updating Chromium on desktop-stable-* branches

  * DNA-111903 [Lin] [Component-based-scrollbar] Old design is displayed
         on Ubuntu 20.04

  * DNA-112914 Visual glitch with HWA enabled in some random places

  * DNA-113137 [WinLin][Sidebar autohide] Sidebar panel is not connected
         with sidebar

  - Update to 105.0.4970.13

  * CHR-9416 Updating Chromium on desktop-stable-* branches

  * DNA-111885 [Address bar] Hover effect on padlock icon is not rounded

  * DNA-112411 Active Tab in Tab Island in Dark Mode should have different
         colour

  * DNA-112431 Dragging tab quickly past last island on the right, causes
         tab to be dropped at the end of tab strip instead
         of at location of the cursor

  * DNA-112878 [Tab strip] Detached tab not restored after restarting
         browser

  * DNA-112900 Crash at opera::component_based::
         ComponentTabDragController::StopViewDragging

  * DNA-112996 Translations for O105

  * DNA-113213 Promote 105 to stable

  - Complete Opera 105 changelog at:

  - Update to 104.0.4944.54

  * DNA-111938 Option 'Automatically hide sidebar' and Full screen makes
         Opera freeze

  * DNA-112241 Stuttering video on some systems with OOP SW H.264 decoding

  * DNA-112636 [Tab strip] Detach button on meeting tabs moves
         on hover and is replaced by close tab

  * DNA-112862 Crash at extensions::BookmarksPrivateAPI::
         OnListenerAdded(extensions::EventListenerInfo const&amp )

  * DNA-112990 Crash when closing tab tooltip and opening Search tabs");

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

  if(!isnull(res = isrpmvuln(pkg:"opera", rpm:"opera~105.0.4970.21~lp155.3.21.1", rls:"openSUSELeap15.5:NonFree"))) {
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
