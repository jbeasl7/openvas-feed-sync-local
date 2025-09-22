# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.1.2024.0223.1");
  script_cve_id("CVE-2024-5493", "CVE-2024-5494", "CVE-2024-5495", "CVE-2024-5496", "CVE-2024-5497", "CVE-2024-5498", "CVE-2024-5499", "CVE-2024-5830", "CVE-2024-5831", "CVE-2024-5832", "CVE-2024-5833", "CVE-2024-5834", "CVE-2024-5835", "CVE-2024-5836", "CVE-2024-5837", "CVE-2024-5838", "CVE-2024-5839", "CVE-2024-5840", "CVE-2024-5841", "CVE-2024-5842", "CVE-2024-5843", "CVE-2024-5844", "CVE-2024-5845", "CVE-2024-5846", "CVE-2024-5847", "CVE-2024-6290", "CVE-2024-6291", "CVE-2024-6292", "CVE-2024-6293");
  script_tag(name:"creation_date", value:"2025-02-25 14:26:30 +0000 (Tue, 25 Feb 2025)");
  script_version("2025-02-26T05:38:41+0000");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-26 16:02:51 +0000 (Thu, 26 Dec 2024)");

  script_name("openSUSE Security Advisory (openSUSE-SU-2024:0223-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2024:0223-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/TVYUZCKNUHHW5G5BDWQLUBT3PJ65O7JM/");
  script_xref(name:"URL", value:"https://blogs.opera.com/desktop/changelog-for-111");
  script_xref(name:"URL", value:"https://blogs.opera.com/desktop/changelog-for-112");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'opera' package(s) announced via the openSUSE-SU-2024:0223-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for opera fixes the following issues:

- Update to 112.0.5197.25
 * CHR-9787 Update Chromium on desktop-stable-126-5197 to
 126.0.6478.127
- The update to chromium 126.0.6478.127 fixes following issues:
 CVE-2024-6290, CVE-2024-6291, CVE-2024-6292, CVE-2024-6293

- Update to 112.0.5197.24
 * CHR-9762 Update Chromium on desktop-stable-126-5197 to
 126.0.6478.62
 * DNA-117001 Crash at base::internal::check_is_test_impl
 (base::NotFatalUntil)
 * DNA-117050 [Settings][Sync] Synchronization options aren't
 visible
 * DNA-117076 [Player] Background of the icons has changed and
 the Tidal icon is now missing
 * DNA-117109 Browser freezes when trying to remove a tab
 * DNA-117181 Translations for O112
 * DNA-117202 Crash at syncer::SyncServiceImpl::NotifyObservers()
 * DNA-117295 Remove emoji names field in picker
 * DNA-117347 Start page is not rendered on first switch to
 workspace after its creation
 * DNA-117431 Promote 112 to stable
- Complete Opera 112 changelog at:
 [link moved to references]
- The update to chromium >= 126.0.6478.54 fixes following issues:
 CVE-2024-5830, CVE-2024-5831, CVE-2024-5832, CVE-2024-5833,
 CVE-2024-5834, CVE-2024-5835, CVE-2024-5836, CVE-2024-5837,
 CVE-2024-5838, CVE-2024-5839, CVE-2024-5840, CVE-2024-5841,
 CVE-2024-5842, CVE-2024-5843, CVE-2024-5844, CVE-2024-5845,
 CVE-2024-5846, CVE-2024-5847

- Update to 111.0.5168.55
 * DNA-116749 Unnecessary icons in the advanced sync settings
 * DNA-116961 Evaluate #vtvd-as-platform-sw-decoder in the field
 * DNA-117003 #vtvd-as-platform-sw-decoder is not registered in
 media unittests

Update to 111.0.5168.43

 * DNA-115228 Adblocker is blocking ads when turned off
 * DNA-116605 Crash at opera::BrowserContentsView::
 NonClientHitTestPoint(gfx::Point const&)
 * DNA-116855 Cannot close tab island's tab when popup
 was hovered
 * DNA-116885 Add chrome.cookies api permission to Rich Hints
 * DNA-116948 [Linux] Theme toggle in settings is not working

Update to 111.0.5168.25

 * CHR-9754 Update Chromium on desktop-stable-125-5168 to
 125.0.6422.142
 * DNA-116089 [Win/Lin] Fullscreen view has rounded corners
 * DNA-116208 The red dot on the Aria's icon is misaligned
 * DNA-116693 X (twitter) logo is not available on
 opera:about page
 * DNA-116737 [Bookmarks] Bookmarks bar favicon have light
 theme color in new window
 * DNA-116769 Extension popup - pin icon is replaced
 * DNA-116850 Fix full package installer link
 * DNA-116852 Promote 111 to stable
 * DNA-116491 Site info popup is cut with dropdown opened
 * DNA-116661 [opera:settings] IPFS/IPNS Gateway box has the
 wrong design
 * DNA-116789 Translations for O111
 * DNA-116813 [React emoji picker] Flag emojis are not load
 correctly
 * DNA-116893 Put 'Show emojis in tab tooltip' in Settings
 * DNA-116918 Translations for 'Show emojis in tab tooltip'

- Complete Opera 111 changelog at:
 [link moved to references]

- The update to chromium ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"opera", rpm:"opera~112.0.5197.25~lp156.2.11.1", rls:"openSUSELeap15.6"))) {
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
