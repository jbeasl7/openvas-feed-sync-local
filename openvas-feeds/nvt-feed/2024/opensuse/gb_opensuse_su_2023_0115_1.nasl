# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833041");
  script_version("2025-03-11T05:38:16+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2022-3196", "CVE-2022-3197", "CVE-2022-3198", "CVE-2022-3199", "CVE-2022-3200", "CVE-2022-3201", "CVE-2022-3445", "CVE-2022-3446", "CVE-2022-3447", "CVE-2022-3448", "CVE-2022-3449", "CVE-2022-3450", "CVE-2022-3723", "CVE-2022-3885", "CVE-2022-3886", "CVE-2022-3887", "CVE-2022-3888", "CVE-2022-3889", "CVE-2022-4262", "CVE-2022-4436", "CVE-2022-4437", "CVE-2022-4438", "CVE-2022-4439", "CVE-2022-4440", "CVE-2023-0471", "CVE-2023-0472", "CVE-2023-0473", "CVE-2023-0474", "CVE-2023-0696", "CVE-2023-0697", "CVE-2023-0698", "CVE-2023-0699", "CVE-2023-0700", "CVE-2023-0701", "CVE-2023-0702", "CVE-2023-0703", "CVE-2023-0704", "CVE-2023-0705", "CVE-2023-0927", "CVE-2023-0928", "CVE-2023-0929", "CVE-2023-0930", "CVE-2023-0931", "CVE-2023-0932", "CVE-2023-0933", "CVE-2023-0941", "CVE-2023-1213", "CVE-2023-1214", "CVE-2023-1215", "CVE-2023-1216", "CVE-2023-1217", "CVE-2023-1218", "CVE-2023-1219", "CVE-2023-1220", "CVE-2023-1221", "CVE-2023-1222", "CVE-2023-1223", "CVE-2023-1224", "CVE-2023-1225", "CVE-2023-1226", "CVE-2023-1227", "CVE-2023-1228", "CVE-2023-1229", "CVE-2023-1230", "CVE-2023-1231", "CVE-2023-1232", "CVE-2023-1233", "CVE-2023-1234", "CVE-2023-1235", "CVE-2023-1236", "CVE-2023-1528", "CVE-2023-1529", "CVE-2023-1530", "CVE-2023-1531", "CVE-2023-1532", "CVE-2023-1533", "CVE-2023-1534", "CVE-2023-2033", "CVE-2023-2133", "CVE-2023-2134", "CVE-2023-2135", "CVE-2023-2136", "CVE-2023-2137", "CVE-2023-2721", "CVE-2023-2722", "CVE-2023-2723", "CVE-2023-2724", "CVE-2023-2725", "CVE-2023-2726");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-27 03:55:00 +0000 (Mon, 27 Mar 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:39:56 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for opera (openSUSE-SU-2023:0115-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5:NonFree");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2023:0115-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/NVMVZHYNGC7MNXWYYPCKCBLKKYAGFJPY");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'opera'
  package(s) announced via the openSUSE-SU-2023:0115-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for opera fixes the following issues:

  - Update to 99.0.4788.13

  * CHR-9290 Update Chromium on desktop-stable-113-4788 to 113.0.5672.127

  * DNA-107317 __delayLoadHelper2 crash in crashreporter

  - The update to chromium 113.0.5672.127 fixes following issues:
       CVE-2023-2721, CVE-2023-2722, CVE-2023-2723, CVE-2023-2724,
       CVE-2023-2725, CVE-2023-2726

  - Update to 99.0.4788.9

  * CHR-9283 Update Chromium on desktop-stable-113-4788 to 113.0.5672.93

  * DNA-107638 Translations for O99

  * DNA-107678 Crash Report [@ BrowserContextKeyedServiceFactory::
         BrowserContextKeyedServiceFactory(char const*,
         BrowserContextDependencyManager*) ]

  * DNA-107795 Fix wrong german translation of 'Close All Duplicate Tabs'

  * DNA-107800 Fonts on section#folder and AddSitePanel not readable when
         animated wallpaper chosen

  * DNA-107840 Promote O99 to stable

  - Update to 98.0.4759.39

  * DNA-102363 ChromeFileSystemAccessPermissionContextTest.
         ConfirmSensitiveEntryAccess_DangerousFile fails

  * DNA-105534 [Add to Opera] Incorrect scroll on modal when browser
         window size is too small

  * DNA-106649 Opening new tab when pinned tab is active gives 2 active
         tabs

  * DNA-107226 Speed Dial freezes and empty space remains after Continue
         booking tile dragging

  * DNA-107435 Building archive_source_release target fails

  * DNA-107441 [Start page] Right mouse click on tile in continue
         on section opens target site in current tab

  * DNA-107508 Crash at permissions::PermissionRecoverySuccessRate
         Tracker::TrackUsage(ContentSettingsType)

  * DNA-107528 Handle real-time SD impression reporting

  * DNA-107546 Context menus broken with one workspace

  * DNA-107548 Paste from Context Menu does not work for Search
         on StartPage

  * DNA-107560 Optimize real-time SD impression reporting");

  script_tag(name:"affected", value:"'opera' package(s) on openSUSE Leap 15.5:NonFree.");

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

if(release == "openSUSELeap15.5:NonFree") {

  if(!isnull(res = isrpmvuln(pkg:"opera", rpm:"opera~99.0.4788.13~lp155.3.6.1", rls:"openSUSELeap15.5:NonFree"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opera", rpm:"opera~99.0.4788.13~lp155.3.6.1", rls:"openSUSELeap15.5:NonFree"))) {
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