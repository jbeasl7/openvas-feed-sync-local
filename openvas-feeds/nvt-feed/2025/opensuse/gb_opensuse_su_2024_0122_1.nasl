# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.1.2024.0122.1");
  script_cve_id("CVE-2024-2883", "CVE-2024-2885", "CVE-2024-2886", "CVE-2024-2887");
  script_tag(name:"creation_date", value:"2025-02-25 14:26:30 +0000 (Tue, 25 Feb 2025)");
  script_version("2025-02-26T05:38:41+0000");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-19 16:04:04 +0000 (Thu, 19 Dec 2024)");

  script_name("openSUSE Security Advisory (openSUSE-SU-2024:0122-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2024:0122-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/FDYESS3DGR73AJ5JNOISN7IW6IOWRXSC/");
  script_xref(name:"URL", value:"https://blogs.opera.com/desktop/changelog-for-109/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'opera' package(s) announced via the openSUSE-SU-2024:0122-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Opera was updated to fix the following issues:

Update to 109.0.5097.45

 * CHR-9416 Updating Chromium on desktop-stable-* branches
 * DNA-114737 [Search box] It's getting blurred when click
 on it, also lower corners are not rounded sometimes
 * DNA-115042 '+' button is not responsive when 30+ tabs opened
 * DNA-115326 Wrong fonts and padding after intake
 * DNA-115392 [Badges] Text displayed in red
 * DNA-115501 'Review your payment' native popup has wrong colors
 * DNA-115809 Enable #show-duplicate-indicator-on-link on
 all streams

Update to 109.0.5097.38

 * CHR-9695 Update Chromium on desktop-stable-123-5097 to
 123.0.6312.87
 * DNA-115156 [Login and Password suggestion] Suggestions are
 bolded and highlight doesn`t fill all area
 * DNA-115313 No video playback on skyshowtime.com
 * DNA-115639 [Version 109][Detached window] Missing functions
 names in light mode
 * DNA-115812 Enable #startpage-opening-animation on all streams
 * DNA-115836 Lucid mode visual issues on H264 videos
- The update to chromium 109.0.5097.38 fixes following issues:
 CVE-2024-2883, CVE-2024-2885, CVE-2024-2886, CVE-2024-2887

Update to 109.0.5097.33

 * CHR-9674 Update Chromium on desktop-stable-123-5097 to
 123.0.6312.46
 * DNA-115357 [Settings] Search toolbar has wrong position
 * DNA-115396 Bolded camera icon when camera access is allowed
 * DNA-115478 AI Prompts in text highlight popup not displayed
 properly
 * DNA-115563 Wallet selector not working
 * DNA-115601 Remove 'moving text' animation in the tab cycler
 * DNA-115645 Internal pages icons unreadable when highlight
 * DNA-115717 'Your extension was disabled because it is
 corrupted' message is displayed to user
 * DNA-115770 Promote 109 to stable
- Complete Opera 109 changelog at:
 [link moved to references]");

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

  if(!isnull(res = isrpmvuln(pkg:"opera", rpm:"opera~109.0.5097.45~lp156.2.3.1", rls:"openSUSELeap15.6"))) {
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
