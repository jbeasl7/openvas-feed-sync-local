# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833568");
  script_version("2025-03-11T05:38:16+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2023-6345", "CVE-2023-6346", "CVE-2023-6347", "CVE-2023-6348", "CVE-2023-6350", "CVE-2023-6351");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-01 20:18:41 +0000 (Fri, 01 Dec 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:11:52 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for opera (openSUSE-SU-2023:0397-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.4:NonFree");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2023:0397-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/V7AX36UQ4VSQGG4N3ZTQIAWX4Z4ZHQAF");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'opera'
  package(s) announced via the openSUSE-SU-2023:0397-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for opera fixes the following issues:

  - Update to 105.0.4970.34

  * DNA-112796 [Import] Import bookmarks and history don't work

  * DNA-113147 Add strength setting for Lucid Mode

  * DNA-113148 Update 'Lucid Mode' button on videos to enable / disable
         split preview

  * DNA-113287 Add strength setting for Lucid Mode in Easy Setup

  * DNA-113310 Remove Lucid Mode for Images

  * DNA-113360 [Lucid Mode] Shadow around lucid mode button

  * DNA-113447 Split preview line should be white

  * DNA-113630 Lucid Mode strength should default to highest (in desktop)

  - Changes in 105.0.4970.29

  * CHR-9416 Updating Chromium on desktop-stable-* branches

  * DNA-113292 Extension icons not shown after restart

  - The update to chromium 119.0.6045.199 fixes following issues:
       CVE-2023-6348, CVE-2023-6347, CVE-2023-6346, CVE-2023-6350,
       CVE-2023-6351, CVE-2023-6345");

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

  if(!isnull(res = isrpmvuln(pkg:"opera", rpm:"opera~105.0.4970.34~lp154.2.65.1", rls:"openSUSELeap15.4:NonFree"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opera", rpm:"opera~105.0.4970.34~lp154.2.65.1", rls:"openSUSELeap15.4:NonFree"))) {
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