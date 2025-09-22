# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.1.2024.0156.1");
  script_cve_id("CVE-2024-3832", "CVE-2024-3833", "CVE-2024-3834", "CVE-2024-3837", "CVE-2024-3838", "CVE-2024-3839", "CVE-2024-3840", "CVE-2024-3841", "CVE-2024-3843", "CVE-2024-3844", "CVE-2024-3845", "CVE-2024-3846", "CVE-2024-3847", "CVE-2024-3914", "CVE-2024-4671", "CVE-2024-5274");
  script_tag(name:"creation_date", value:"2025-02-25 14:26:30 +0000 (Tue, 25 Feb 2025)");
  script_version("2025-02-26T05:38:41+0000");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-11-27 18:12:51 +0000 (Wed, 27 Nov 2024)");

  script_name("openSUSE Security Advisory (openSUSE-SU-2024:0156-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2024:0156-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/PYKI7FIDICKYHO5TLIGQUUCUF2ATFWPR/");
  script_xref(name:"URL", value:"https://blogs.opera.com/desktop/changelog-for-110/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'opera' package(s) announced via the openSUSE-SU-2024:0156-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for opera fixes the following issues:

Update to 110.0.5130.64

 * CHR-9748 Update Chromium on desktop-stable-124-5130
 to 124.0.6367.243
 * DNA-116317 Create outline or shadow around emojis on tab strip
 * DNA-116320 Create animation for emoji disappearing from
 tab strip
 * DNA-116564 Assign custom emoji from emoji picker
 * DNA-116690 Make chrome://emoji-picker attachable by webdriver
 * DNA-116732 Introduce stat event for setting / unsetting emoji
 on a tab
 * DNA-116753 Emoji picker does not follow browser theme
 * DNA-116755 Record tab emojis added / removed
 * DNA-116777 Enable #tab-art on all streams

Update to 110.0.5130.49

 * CHR-9416 Updating Chromium on desktop-stable-* branches
 * DNA-116706 [gpu-crash] Crash at SkGpuShaderImageFilter::
 onFilterImage(skif::Context const&)

Update to 110.0.5130.39

 * DNA-115603 [Rich Hints] Pass trigger source to the Rich Hint
 * DNA-116680 Import 0-day fix for CVE-2024-5274

Update to 110.0.5130.35

 * CHR-9721 Update Chromium on desktop-stable-124-5130 to
 124.0.6367.202
 * DNA-114787 Crash at views::View::DoRemoveChildView(views::
 View*, bool, bool, views::View*)
 * DNA-115640 Tab island is not properly displayed after
 drag&drop in light theme
 * DNA-116191 Fix link in RTV Euro CoS
 * DNA-116218 Crash at SkGpuShaderImageFilter::onFilterImage
 (skif::Context const&)
 * DNA-116241 Update affiliation link for media expert
 'Continue On'
 * DNA-116256 Crash at TabHoverCardController::UpdateHoverCard
 (opera::TabDataView*, TabHoverCardController::UpdateType,
 bool)
 * DNA-116270 Show 'Suggestions' inside expanding Speed Dial
 field
 * DNA-116474 Implement the no dynamic hover approach
 * DNA-116493 Make sure that additional elements like
 (Sync your browser) etc. doesn't shift content down on page
 * DNA-116515 Import 0-day fix from Chromium '[wasm-gc] Only
 normalize JSObject targets in SetOrCopyDataProperties'
 * DNA-116543 Twitter migrate to x.com
 * DNA-116552 Change max width of the banner
 * DNA-116569 Twitter in Panel loading for the first time opens
 two Tabs automatically
 * DNA-116587 Translate settings strings for every language

The update to chromium 124.0.6367.202 fixes following issues:
 CVE-2024-4671

Update to 110.0.5130.23

 * CHR-9706 Update Chromium on desktop-stable-124-5130 to
 124.0.6367.62
 * DNA-116450 Promote 110 to stable

- Complete Opera 110 changelog at:
 [link moved to references]

- The update to chromium 124.0.6367.62 fixes following issues:
 CVE-2024-3832, CVE-2024-3833, CVE-2024-3914, CVE-2024-3834,
 CVE-2024-3837, CVE-2024-3838, CVE-2024-3839, CVE-2024-3840,
 CVE-2024-3841, CVE-2024-3843, CVE-2024-3844, CVE-2024-3845,
 CVE-2024-3846, CVE-2024-3847

- Update to 109.0.5097.80

 * DNA-115738 Crash at extensions::ExtensionRegistry::
 GetExtensionById(std::__Cr::basic_string const&, int)
 * DNA-115797 [Flow] Never ending loading while connecting to flow
 * DNA-116315 Chat GPT in ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'opera' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"opera", rpm:"opera~110.0.5130.64~lp156.2.6.1", rls:"openSUSELeap15.6"))) {
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
