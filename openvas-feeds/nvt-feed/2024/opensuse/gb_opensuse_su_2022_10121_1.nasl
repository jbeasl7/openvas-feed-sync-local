# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833645");
  script_version("2025-03-11T05:38:16+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2022-3075");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-30 18:47:00 +0000 (Fri, 30 Sep 2022)");
  script_tag(name:"creation_date", value:"2024-03-04 07:54:21 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for opera (openSUSE-SU-2022:10121-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5:NonFree");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2022:10121-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/N6OVSTQYBJJJ7LGB4PRJG4CP2G7JK35D");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'opera'
  package(s) announced via the openSUSE-SU-2022:10121-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for opera fixes the following issues:

     Update to 90.0.4480.84

  - DNA-101690 Cherry-pick fix for CVE-2022-3075 from chromium

     Update to 90.0.4480.80

  - DNA-99188 Tab Tooltip doesn't disappear

  - DNA-100664 Shopping corner widget

  - DNA-100843 Options to install and update VPN Pro app, when it's not
       installed

  - DNA-100901 Disappearing 'X' when closing tabs.

  - DNA-101093 Changing News section is not working

  - DNA-101246 Use long tail list for suggesting instead of current Speed
       Dial Suggestions

  - DNA-101278 PDF don't work on Opera with CN location

  - DNA-101312 Allow changing logged in user with BrowserAPI

  - DNA-101315 Can not connect to free VPN in private window

  - DNA-101411 [Linux] Clicking VpnPopup Settings to 'vpnWithDisclaimer'
       leads to black popup

  - DNA-101422 Crash at void content::NavigationControllerImpl::
       NavigateToExistingPendingEntry(content::ReloadType, int, bool)

  - DNA-101429 News loads for Global-EN language by default

  - DNA-101482 Crash at ProfileKey::GetProtoDatabaseProvider()

  - DNA-101485 Crash at base::SequencedTaskRunnerHandle::Get() via
       extensions::OperaTouchPrivateGetImageFunction::PerformGetImage

  - DNA-101524 [Mac] Tab should be highlighted again after dismissing
       context menu

  - DNA-101549 Crash at views::View::IsMouseHovered()");

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

  if(!isnull(res = isrpmvuln(pkg:"opera", rpm:"opera~90.0.4480.84~lp155.3.3.1", rls:"openSUSELeap15.5:NonFree"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opera", rpm:"opera~90.0.4480.84~lp155.3.3.1", rls:"openSUSELeap15.5:NonFree"))) {
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