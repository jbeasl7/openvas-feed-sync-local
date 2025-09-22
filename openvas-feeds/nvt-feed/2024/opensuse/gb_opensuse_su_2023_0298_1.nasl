# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833446");
  script_version("2025-03-11T05:38:16+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2023-5186", "CVE-2023-5187", "CVE-2023-5217");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-29 18:37:00 +0000 (Fri, 29 Sep 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:46:28 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for opera (openSUSE-SU-2023:0298-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.4:NonFree");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2023:0298-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/V5KRGLOBRAIYNFCNZH4YM2ETGNMPQEKZ");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'opera'
  package(s) announced via the openSUSE-SU-2023:0298-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for opera fixes the following issues:

  - Update to 103.0.4928.16

  * CHR-9416 Updating Chromium on desktop-stable-* branches

  * CHR-9433 Update Chromium on desktop-stable-117-4928 to 117.0.5938.89

  * CHR-9449 Update Chromium on desktop-stable-117-4928 to 117.0.5938.132

  * DNA-110337 Opera Intro extension custom versions

  * DNA-111454 Player animations visual adjustments

  * DNA-111618 Turn on #password-generator on all streams

  * DNA-111645 Turn on flag #player-service-react on developer stream

  * DNA-111708 Player home page is shown while music service is being
         loaded

  * DNA-111722 [Tab strip][Tab island] Add tab in tab island button
         appears after size of tabs is changed

  * DNA-111727 JsonPrefStore is created twice for Local State file

  * DNA-111838 Promote 103.0 to stable

  * DNA-111845 Turn on flag #player-service-react on all streams

  * DNA-111868 Translations for O103

  * DNA-111874 OMenu and Context Menus has transparent few px border

  - The update to chromium 117.0.5938.89 fixes following issues:
       CVE-2023-5217, CVE-2023-5186, CVE-2023-5187

  - Complete Opera 103 changelog at:

  - Update to 102.0.4880.78

  * DNA-110952 Crash at base::subtle::RefCountedBase:: ReleaseImpl() const

  - Update to 102.0.4880.70

  * DNA-105016 Do not open file selector when closing easy files dialog
         with 'close this popup' option

  * DNA-110437 Extensions font color in dark mode makes the text not
         visible

  * DNA-110443 Crash at EasyFilesView::ShowFileSelector

  * DNA-111231 Amazon Music logo update in sidebar Player

  * DNA-111280 Make import from Crypto Browser to Opera Browser easier

  * DNA-111355 [Sidebar] DevTools is not working correctly in with sidebar
         panel

  * DNA-111708 Player home page is shown while music service is being
         loaded

  * DNA-111162 Refresh Player home page

  * DNA-111164 Implement animation in Player home page

  - Update to 102.0.4880.56

  * DNA-110785 Crash at static void base::allocator::
         UnretainedDanglingRawPtrDetectedDumpWithoutCrashing (unsigned __int64)

  * DNA-110973 Crash after dragging tab from island to another screen

  * DNA-111199 Disable user_education tests from component_unittests

  * DNA-111369 Crash at views::View::DoRemoveChildView(views:: View*,
         bool, bool, views::View*)

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

  if(!isnull(res = isrpmvuln(pkg:"opera", rpm:"opera~103.0.4928.16~lp154.2.53.1", rls:"openSUSELeap15.4:NonFree"))) {
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
