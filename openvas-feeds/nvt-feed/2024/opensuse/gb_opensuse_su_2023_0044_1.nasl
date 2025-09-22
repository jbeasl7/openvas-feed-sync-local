# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833785");
  script_version("2025-03-11T05:38:16+0000");
  script_cve_id("CVE-2023-0471", "CVE-2023-0472", "CVE-2023-0473", "CVE-2023-0474");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-06 21:28:21 +0000 (Mon, 06 Feb 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:42:05 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for opera (openSUSE-SU-2023:0044-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.4:NonFree");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2023:0044-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/RKK4BPBXIKVPZDG525Y5FDNCGJ2JWXLQ");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'opera'
  package(s) announced via the openSUSE-SU-2023:0044-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for opera fixes the following issues:

     Update to 95.0.4635.25

  * CHR-9173 Update Chromium on desktop-stable-109-4635 to 109.0.5414.120

  * DNA-104150 Turn on #consent-flow-settings on master

  * DNA-104733 Crash at extensions::SyncPrivateGetSyncStateFunction::Run()

  * DNA-104761 Translations for O95

  * DNA-104814 [StartPage] Inline autocomplete messes up selection

  * DNA-104887 Promote O95 to stable

  * DNA-104908 Enable #consent-flow-settings on all streams

  - The update to chromium 109.0.5414.120 fixes following issues:
       CVE-2023-0471, CVE-2023-0472, CVE-2023-0473, CVE-2023-0474


  - Update to 94.0.4606.76

  * DNA-104276 News categories layers messed up in other languages

  - Update to 94.0.4606.65

  * DNA-102726 [SD][Folder] When trying to drop SD from folder back to
         folder, new folder is created

  * DNA-102730 [SD][Add to Opera] Remove strip at the top of modal and
         move 'x' button to be in line with Add to Opera' text

  * DNA-102732 [SD][Folders] Add option to merge folders by drag and drop

  * DNA-102747 [SD][Folders] Empty SD folder is not visible

  * DNA-102763 [SD] Animate changing between Use bigger tiles
         on and off

  * DNA-102847 [SD][Folders] SD displayed on folder tile should be aligned
         to left

  * DNA-102855 [SD] Add SD by drag and dropping link

  * DNA-102882 [SD][News][Continue on][Suggestion] Do not focus on
         opened page when opening in new tab

  * DNA-102936 [News Categories] Categories become invisible after
         minimizing browser window

  * DNA-102988 [News categories] Only games category displayed after
         changing browser language

  * DNA-103000 [News Categories] Selected categories not saved after
         restarting browser

  * DNA-103001 [News Categories] 'x' button invisible in 'Choose language
         and country' on light theme

  * DNA-103002 [News Categories] Changes in 'Choose language and country'
         modal not saved on esc or clicking outside of modal

  * DNA-103015 [News locales] Pref startpage.news_locales updated
         only when close/done the moda, initial value not set

  * DNA-103097 [Settings] Enable 'Adjust Speed Dial animations for slower
         hardware' settings option to have effect

  * DNA-103098 [SD] No big icon for decathlon.pl

  * DNA-103110 Strange animation when dragging tiles

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

  if(!isnull(res = isrpmvuln(pkg:"opera", rpm:"opera~95.0.4635.25~lp154.2.38.1", rls:"openSUSELeap15.4:NonFree"))) {
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
