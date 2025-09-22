# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833701");
  script_version("2025-03-11T05:38:16+0000");
  script_cve_id("CVE-2023-5472");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-01 19:04:53 +0000 (Wed, 01 Nov 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:41:18 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for opera (openSUSE-SU-2023:0353-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.4:NonFree");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2023:0353-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/U2US6TNF7TPGYAPZH3LICWH3F6C4MLDQ");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'opera'
  package(s) announced via the openSUSE-SU-2023:0353-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for opera fixes the following issues:

  - Update to 104.0.4944.36

  * CHR-9492 Update Chromium on desktop-stable-118-4944 to 118.0.5993.118

  * DNA-112757 [Tab close button] Close button is cut when a lot tabs
         are opened

  - The update to chromium 118.0.5993.118 fixes following issues:
       CVE-2023-5472

  - Update to 104.0.4944.33

  * CHR-9487 Update Chromium on desktop-stable-118-4944 to 118.0.5993.96

  * DNA-111963 Show duplicate indicator when hovering tab in tab tooltip

  - Changes in 104.0.4944.28

  * DNA-112454 [Start Page] No context menu in Search bar using right
         button of mouse

  * DNA-112053 Context menu is too large on Mac

  * DNA-111989 Favicons are displayed too close to titles in history menu");

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

  if(!isnull(res = isrpmvuln(pkg:"opera", rpm:"opera~104.0.4944.36~lp154.2.59.1", rls:"openSUSELeap15.4:NonFree"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opera", rpm:"opera~104.0.4944.36~lp154.2.59.1", rls:"openSUSELeap15.4:NonFree"))) {
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