# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833336");
  script_version("2025-03-11T05:38:16+0000");
  script_cve_id("CVE-2023-0927", "CVE-2023-0928", "CVE-2023-0929", "CVE-2023-0930", "CVE-2023-0931", "CVE-2023-0932", "CVE-2023-0933", "CVE-2023-0941");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-28 02:17:05 +0000 (Tue, 28 Feb 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:22:56 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for opera (openSUSE-SU-2023:0066-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.4:NonFree");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2023:0066-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/RPPOT4TKRDH3DHWEAFPF5VECCRLHRJ6N");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'opera'
  package(s) announced via the openSUSE-SU-2023:0066-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for opera fixes the following issues:

     Update to 96.0.4693.31

  * CHR-9206 Update Chromium on desktop-stable-110-4693 to 110.0.5481.178

  * DNA-104492 [Stable A/B Test] React Start Page for Austria 50%

  * DNA-104660 Browser crash when calling window.opr.authPrivate API in a
       private mode

  * DNA-105000 Crash at non-virtual thunk to
       SadTabView::OnBoundsChanged(gfx::Rect const&amp )

  * DNA-105138 Hang-up button is red in video popout

  * DNA-105211 Johnny5  Prepare extension to be usable in Desktop

  * DNA-105377 Add API for extension to be able to open sidebar panel

  * DNA-105378 Add 'AI Shorten' functionality to search/copy tooltip

  * DNA-105410 Change Popup functionality depending on number
       of words selected

  * DNA-105429 Fix privileges for Shodan api

  * DNA-105434 Change popup depending on number of words

  * DNA-105442 Fix Update &amp  Recovery page styling

  * DNA-105455 [Search box] Search box does not resize dynamically

  * DNA-105606 Enabling news by default on SP test- 2

     The update to chromium 110.0.5481.178 fixes following issues:
     CVE-2023-0927, CVE-2023-0928, CVE-2023-0929, CVE-2023-0930, CVE-2023-0931,
     CVE-2023-0932, CVE-2023-0933, CVE-2023-0941");

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

  if(!isnull(res = isrpmvuln(pkg:"opera", rpm:"opera~96.0.4693.31~lp154.2.44.1", rls:"openSUSELeap15.4:NonFree"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opera", rpm:"opera~96.0.4693.31~lp154.2.44.1", rls:"openSUSELeap15.4:NonFree"))) {
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