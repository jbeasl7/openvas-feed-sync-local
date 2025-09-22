# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856271");
  script_cve_id("CVE-2024-5493", "CVE-2024-5494", "CVE-2024-5495", "CVE-2024-5496", "CVE-2024-5497", "CVE-2024-5498", "CVE-2024-5499");
  script_tag(name:"creation_date", value:"2024-07-07 04:00:22 +0000 (Sun, 07 Jul 2024)");
  script_version("2025-02-26T05:38:40+0000");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:40 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-26 16:07:06 +0000 (Thu, 26 Dec 2024)");

  script_name("openSUSE Security Advisory (openSUSE-SU-2024:0187-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2024:0187-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/6B5SLGYT6SKW4EUYZ5XLYQG66Y433XMH/");
  script_xref(name:"URL", value:"https://blogs.opera.com/desktop/changelog-for-111");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'opera' package(s) announced via the openSUSE-SU-2024:0187-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for opera fixes the following issues:

- Update to 111.0.5168.43

 * DNA-115228 Adblocker is blocking ads when turned off
 * DNA-116605 Crash at opera::BrowserContentsView::
 NonClientHitTestPoint(gfx::Point const&)
 * DNA-116855 Cannot close tab island's tab when popup
 was hovered
 * DNA-116885 Add chrome.cookies api permission to Rich Hints
 * DNA-116948 [Linux] Theme toggle in settings is not working

- Update to 111.0.5168.25

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
- The update to chromium 125.0.6422.142 fixes following issues:
 CVE-2024-5493, CVE-2024-5494, CVE-2024-5495, CVE-2024-5496,
 CVE-2024-5497, CVE-2024-5498, CVE-2024-5499

- Update to 110.0.5130.64

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

- Update to 110.0.5130.49

 * CHR-9416 Updating Chromium on desktop-stable-* branches
 * DNA-116706 [gpu-crash] Crash at SkGpuShaderImageFilter::
 onFilterImage(skif::Context const&)");

  script_tag(name:"affected", value:"'opera' package(s) on openSUSE Leap 15.5.");

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

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"opera", rpm:"opera~111.0.5168.43~lp155.3.51.1", rls:"openSUSELeap15.5"))) {
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
