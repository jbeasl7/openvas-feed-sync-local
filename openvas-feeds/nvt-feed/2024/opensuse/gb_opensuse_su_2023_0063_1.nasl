# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833380");
  script_version("2025-03-11T05:38:16+0000");
  script_cve_id("CVE-2023-0696", "CVE-2023-0697", "CVE-2023-0698", "CVE-2023-0699", "CVE-2023-0700", "CVE-2023-0701", "CVE-2023-0702", "CVE-2023-0703", "CVE-2023-0704", "CVE-2023-0705");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-16 15:16:21 +0000 (Thu, 16 Feb 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:57:53 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for opera (openSUSE-SU-2023:0063-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.4:NonFree");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2023:0063-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/LBM3FQOGJ4SXNVSG3CBTTQRLHJDHQSI3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'opera'
  package(s) announced via the openSUSE-SU-2023:0063-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for opera fixes the following issues:

     Update to 96.0.4693.20

  * CHR-9191 Update Chromium on desktop-stable-110-4693 to 110.0.5481.78

  * CHR-9197 Update Chromium on desktop-stable-110-4693 to 110.0.5481.100

  * DNA-105308 Translations for O96

  * DNA-105395 Fix missing resources errors on About and Update &amp  Recovery
         pages

  - Complete Opera 96.0 changelog at:

  - The update to chromium 110.0.5481.78 fixes following issues:
       CVE-2023-0696, CVE-2023-0697, CVE-2023-0698, CVE-2023-0699,
       CVE-2023-0700, CVE-2023-0701, CVE-2023-0702, CVE-2023-0703,
       CVE-2023-0704, CVE-2023-0705

     Update to 95.0.4635.46

  * DNA-104601 Crash at
         opera::EasyShareButtonControllerTabHelper::StartOnboarding()

  * DNA-104936 Set new Baidu search string

  * DNA-105084 Prepare to turning on 'Rich entities'

     Update to 95.0.4635.37

  * DNA-104366 Turn #speed-dial-custom-image on developer

  * DNA-104370 Pictures in news dont show

  * DNA-104384 [News] Change News to be disabled by default

  * DNA-104393 [Continue on] Weird look of item counter in collapsed
         Continue shopping after refreshing page

  * DNA-104394 [Continue on] Continue shopping show up collapsed

  * DNA-104421 Mechanism to detect installed player

  * DNA-104439 Merge with GX implementation

  * DNA-104492 [Stable A/B Test] React Start Page for Austria 50%

  * DNA-104523 [Add to Opera][Folders][Edit] Black font on dark background
         in modals when light theme with dark wallpaper is selected

  * DNA-104525 [Choose language and country] Modal does not adapt when
         wallpaper does not match theme

  * DNA-104609 [SD][Folders] Incorrect order of tiles in folder when
         merging folder with single tile

  * DNA-104612 [News] Invisible button in news category.

  * DNA-104614 Do not allow to create folder with the same name to prevent
         automerging

  * DNA-104898 [Edit tile] Adjust icon size of tile in edit-form-modal");

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

  if(!isnull(res = isrpmvuln(pkg:"opera", rpm:"opera~96.0.4693.20~lp154.2.41.1", rls:"openSUSELeap15.4:NonFree"))) {
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
