# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833717");
  script_cve_id("CVE-2024-0222", "CVE-2024-0223", "CVE-2024-0224", "CVE-2024-0225");
  script_tag(name:"creation_date", value:"2024-03-04 12:55:59 +0000 (Mon, 04 Mar 2024)");
  script_version("2025-02-26T05:38:40+0000");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:40 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-08 19:41:43 +0000 (Mon, 08 Jan 2024)");

  script_name("openSUSE Security Advisory (openSUSE-SU-2024:0016-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2024:0016-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/UY4JPWBKZYYGRANOGGULA6VZCO66CVNC/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'opera' package(s) announced via the openSUSE-SU-2024:0016-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for opera fixes the following issues:

opera was updated to 106.0.4998.28

 * CHR-9566 Update Chromium on desktop-stable-120-4998 to
 120.0.6099.200
 * DNA-113161 [Weather] 'Weather Location' description is almost
 invisible in dark mode
 * DNA-113351 'Previous tile' should be the same size
 as 'next tile'
 * DNA-113443 Crash at opera::ComponentTabCyclerView::
 HighlightContents(content::WebContents*, bool)
 * DNA-114170 [Google Meet][Tab] Links from Google Meet open
 as blank tabs till change workspace

- The update to chromium 120.0.6099.200 fixes following issues:
 CVE-2024-0222, CVE-2024-0223, CVE-2024-0224, CVE-2024-0225");

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

  if(!isnull(res = isrpmvuln(pkg:"opera", rpm:"opera~106.0.4998.28~lp155.3.30.1", rls:"openSUSELeap15.5"))) {
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
