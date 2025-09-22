# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.1.2025.0111.1");
  script_cve_id("CVE-2025-2783");
  script_tag(name:"creation_date", value:"2025-04-01 14:12:50 +0000 (Tue, 01 Apr 2025)");
  script_version("2025-05-01T05:40:03+0000");
  script_tag(name:"last_modification", value:"2025-05-01 05:40:03 +0000 (Thu, 01 May 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (openSUSE-SU-2025:0111-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2025:0111-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/SJEX6ZT5W5GYLZEQIA7L2J32HG4KGMAX/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'opera' package(s) announced via the openSUSE-SU-2025:0111-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for opera fixes the following issues:

- Update to 117.0.5408.163
 * DNA-120683 [Issue back] Sometimes onboarding is blank
 and useless
 * DNA-121682 Backport fix for CVE-2025-2783 to O132, O133,
 GX132 and Air132
- Changes in 117.0.5408.154
 * DNA-121210 After enabling tab scrolling, the tab bar narrows
 on both the left and right sides
 * DNA-121560 Extension updates which requires manual
 confirmation do not work
- Changes in 117.0.5408.142
 * DNA-121314 Use the extra palette color to paint the frame
 * DNA-121321 Refactor ColorSet struct
 * DNA-121444 Crash at opera::VibesServiceImpl::VibesServiceImpl
 * DNA-121477 Add unit tests for ColorSet
 * DNA-121488 [ASAN] ColorSetTest.DefaultConstructor fails
- Changes in 117.0.5408.93
 * DNA-118548 After pressing Ctrl+F / Cmd+F on the Start Page
 (SP), the focus should be on the search bar
 * DNA-121183 Add 'transparent UI' parameter to Vibe logic
 * DNA-121184 Allow to specify extra palette for window
 background in Vibe logic
 * DNA-121232 Enable Slack, Discord and Bluesky flag on
 all streams
 * DNA-121237 Crash at opera::SidebarExpandViewEmbedder::Position
 * DNA-121322 [Opera Translate] [Redesign] Expired #translator
 flag
 * DNA-121385 Remove 'passkey' string

- Update to 117.0.5408.53
 * DNA-120848 Add 'x' button to close/dismiss translate popup
 * DNA-120849 Dismissing popup adds language to never translate
 from list
 * DNA-120951 Optimize MFSVE output handling
 * DNA-120972 Crash at TabDesktopMediaList::Refresh
 * CHR-9964 Update Chromium on desktop-stable-132-5408 to
 132.0.6834.210 Changes in 117.0.5408.47
 * CHR-9961 Update Chromium on desktop-stable-132-5408 to
 132.0.6834.209");

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

  if(!isnull(res = isrpmvuln(pkg:"opera", rpm:"opera~117.0.5408.163~lp156.2.32.1", rls:"openSUSELeap15.6"))) {
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
