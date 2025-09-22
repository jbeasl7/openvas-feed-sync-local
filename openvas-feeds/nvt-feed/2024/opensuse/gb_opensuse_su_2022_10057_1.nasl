# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833228");
  script_version("2025-03-11T05:38:16+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2022-2007", "CVE-2022-2008", "CVE-2022-2010", "CVE-2022-2011", "CVE-2022-2294");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-03 17:53:39 +0000 (Wed, 03 Aug 2022)");
  script_tag(name:"creation_date", value:"2024-03-04 07:35:47 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for opera (openSUSE-SU-2022:10057-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.4:NonFree");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2022:10057-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/RJUDCH46YEJXHUW2NNEMWI2TSQIO7ON2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'opera'
  package(s) announced via the openSUSE-SU-2022:10057-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for opera fixes the following issues:
  opera was updated to 88.0.4412.74:

  - DNA-100645 Cherry-pick CVE-2022-2294 onto stabilization branches
  Update to 88.0.4412.53

  - DNA-99108 [Lin] Options on video pop out not possible to change

  - DNA-99832 On automatic video popout, close button should not stop video

  - DNA-99833 Allow turning on and off of each 'BABE' section from gear
         icon

  - DNA-99852 Default browser in Mac installer

  - DNA-99993 Crashes in AudioFileReaderTest,
         FFmpegAACBitstreamConverterTest

  - DNA-100045 iFrame Exception not unblocked with Acceptable Ads

  - DNA-100291 Update snapcraft uploading/releasing in scripts to use
         craft store
  Changes in 88.0.4412.40

  - CHR-8905 Update chromium on desktop-stable-102-4412 to 102.0.5005.115

  - DNA-99713 Sizing issues with video conferencing controls in PiP window

  - DNA-99831 Add 'back to tab' button like on video pop-out

  - The update to chromium 102.0.5005.115 fixes following issues:
       CVE-2022-2007, CVE-2022-2008, CVE-2022-2010, CVE-2022-2011
  Changes in 88.0.4412.27

  - DNA-99725 Crash at opera::ModalDialogViews::Show()

  - DNA-99752 Do not allow to uncheck all lists for adBlock

  - DNA-99918 Enable #scrollable-tab-strip on desktop-stable-102-4412

  - DNA-99969 Promote O88 to stable

  - Complete Opera 88.0 changelog at:

  - DNA-99478 Top Sites dont always has big icon

  - DNA-99702 Enable Acceptable Ads for stable stream

  - DNA-99725 Crash at opera::ModalDialogViews::Show()

  - DNA-99752 Do not allow to uncheck all lists for adBlock

  - Update to 87.0.4390.36

  - CHR-8883 Update chromium on desktop-stable-101-4390 to 101.0.4951.67

  - DNA-99190 Investigate windows installer signature errors on win7

  - DNA-99502 Sidebar  API to open panels

  - DNA-99593 Report sad tab displayed counts per kind

  - DNA-99628 Personalized Speed Dial context menu issue fix");

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

  if(!isnull(res = isrpmvuln(pkg:"opera", rpm:"opera~88.0.4412.74~lp154.2.11.1", rls:"openSUSELeap15.4:NonFree"))) {
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
