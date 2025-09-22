# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833072");
  script_cve_id("CVE-2024-1059", "CVE-2024-1060", "CVE-2024-1077", "CVE-2024-1283", "CVE-2024-1284");
  script_tag(name:"creation_date", value:"2024-03-04 12:55:01 +0000 (Mon, 04 Mar 2024)");
  script_version("2025-02-26T05:38:40+0000");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:40 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-14 18:19:17 +0000 (Wed, 14 Feb 2024)");

  script_name("openSUSE Security Advisory (openSUSE-SU-2024:0053-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2024:0053-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/JEOW7JNA5URR7GH7G6H4JCJ2CMZKOQEE/");
  script_xref(name:"URL", value:"https://blogs.opera.com/desktop/changelog-for-107/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'opera' package(s) announced via the openSUSE-SU-2024:0053-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for opera fixes the following issues:

- Update to 107.0.5045.21
 * CHR-9604 Update Chromium on desktop-stable-121-5045
 to 121.0.6167.160
 * DNA-114167 Crash at TopLevelStorageAccessPermissionContext::
 DecidePermission(permissions::PermissionRequestData, base::
 OnceCallback)
 * DNA-114303 Crash at auto std::__Cr::remove_if(auto, auto,
 base::ObserverList::Compact()::'lambda'(auto const&))
 * DNA-114478 Start Page opening animation refresh
 * DNA-114553 Change search box animation
 * DNA-114723 [Search box] No option to highlight typed text
 * DNA-114806 [Tab cycler] Domain address should be bolded
 * DNA-114846 Translations for O107
 * DNA-114924 Crash at opera::SuggestionModelBase::
 NavigateTo(WindowOpenDisposition)
- The update to chromium 121.0.6167.160 fixes following issues:
 CVE-2024-1283, CVE-2024-1284

- Update to 107.0.5045.15
 * CHR-9593 Update Chromium on desktop-stable-121-5045 to
 121.0.6167.140
 * DNA-114421 Animate text in tab cycler from the center of
 the screen
 * DNA-114519 Crash at media::AVStreamToVideoDecoderConfig
 (AVStream const*, media::VideoDecoderConfig*)
 * DNA-114537 Default value for synchronization changed from
 'Do not sync data' to 'Customise sync'
 * DNA-114554 Add shadow to tab thumbnails in tab cycler
 * DNA-114555 Fade out long tab titles
 * DNA-114686 [Import] Import from Opera Crypto is marked as
 done even when Crypto is not installed
 * DNA-114691 Update font colors
 * DNA-114692 Update shadow (glow) of tabs
 * DNA-114693 Update position of text and tabs when cycling
 through tabs
 * DNA-114790 [Linux] Unwanted 1px top border in full screen mode
- Complete Opera 107 changelog at:
 [link moved to references]
- The update to chromium 121.0.6167.140 fixes following issues:
 CVE-2024-1059, CVE-2024-1060, CVE-2024-1077

- Update to 106.0.4998.70
 * DNA-112467 Shadow on Opera popups
 * DNA-114414 The 'Move to' workspace submenu from tab strip
 stays blue when its submenu item is selected

- Update to 106.0.4998.66
 * CHR-9416 Updating Chromium on desktop-stable-* branches
 * DNA-114489 Release and update opera:intro extension version
 in Opera");

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

  if(!isnull(res = isrpmvuln(pkg:"opera", rpm:"opera~107.0.5045.21~lp155.3.36.1", rls:"openSUSELeap15.5"))) {
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
