# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833412");
  script_version("2025-03-11T05:38:16+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2022-1364", "CVE-2022-1633", "CVE-2022-1634", "CVE-2022-1635", "CVE-2022-1636", "CVE-2022-1637", "CVE-2022-1638", "CVE-2022-1639", "CVE-2022-1640", "CVE-2022-1641");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-28 14:56:15 +0000 (Thu, 28 Jul 2022)");
  script_tag(name:"creation_date", value:"2024-03-04 07:24:06 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for opera (openSUSE-SU-2022:0156-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.4:NonFree");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2022:0156-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/ONQWTUXG3A64JMVWQXBWVRYQ2YMCSF5T");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'opera'
  package(s) announced via the openSUSE-SU-2022:0156-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for opera fixes the following issues:
  Update to 87.0.4390.25:

  - CHR-8870 Update chromium on desktop-stable-101-4390 to 101.0.4951.64

  - DNA-99209 Enable #easy-files-multiupload on all streams

  - DNA-99325 Use a preference to set number of recent searches and
         recently closed in unfiltered dropdown

  - DNA-99353 Translations for O87

  - DNA-99365 Adding title to the first category duplicates categories
         titles in the dropdown

  - DNA-99385 Feedback button in filtered dropdown can overlap with
         other web buttons for highlighted suggestion

  - DNA-99391 Add bookmarks at the bottom of a bookmarks bar folder

  - DNA-99491 Suggestion is not immediately removed form recent searches
         view in dropdown.

  - DNA-99501 Promote O87 to stable

  - DNA-99504 Switch to tab button is not aligned to the right for
         some categories in dropdown

  - The update to chromium 101.0.4951.64 fixes following issues:
       CVE-2022-1633, CVE-2022-1634, CVE-2022-1635, CVE-2022-1636,
       CVE-2022-1637, CVE-2022-1638, CVE-2022-1639, CVE-2022-1640, CVE-2022-1641

  - Complete Opera 87.0 changelog at:

  - Update to 86.0.4363.59

  - DNA-99021 Crash in sidebar when extension of sidebar item was
         uninstalled

  - DNA-99359 Crash at opera::
         ContinueShoppingExpiredProductRemoverImpl::RemoveExpiredProducts()

  - Update to 86.0.4363.50

  - DNA-68493 Opera does not close address field drop-down when dragging
         text from the address field

  - DNA-99003 Crash at views::Widget::GetNativeView() const

  - DNA-99133 BrowserSidebarWithProxyAuthTest.PreloadWithWebModalDialog
         fails

  - DNA-99230 Switching search engine with shortcut stopped working after
         DNA-99178

  - DNA-99317 Make history match appear on top

  - Update to 86.0.4363.32

  - DNA-98510 Blank icon in sidebar setup

  - DNA-98525 Unable to drag tab to far right

  - DNA-98893 Sound indicator is too precise in Google Meet

  - DNA-98919 Shopping corner internal API access update

  - DNA-98924 Tab tooltip gets stuck on screen

  - DNA-98981 Enable easy-files-multiupload on developer stream

  - DNA-99041 Move Shopping Corner to sidebar entry

  - DNA-99061 Enable #address-bar-dropdown-categories on all streams

  - DNA-99062 Create flag to show top sites and recently closed in
         unfiltered suggestions

  - DNA-99064 Hard to drag &amp  drop current URL to a specific folder
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

  if(!isnull(res = isrpmvuln(pkg:"opera", rpm:"opera~87.0.4390.25~lp154.2.8.1", rls:"openSUSELeap15.4:NonFree"))) {
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
