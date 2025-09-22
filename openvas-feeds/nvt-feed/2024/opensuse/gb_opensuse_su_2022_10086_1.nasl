# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833752");
  script_version("2025-03-11T05:38:16+0000");
  script_cve_id("CVE-2022-2603", "CVE-2022-2604", "CVE-2022-2605", "CVE-2022-2606", "CVE-2022-2607", "CVE-2022-2608", "CVE-2022-2609", "CVE-2022-2610", "CVE-2022-2611", "CVE-2022-2612", "CVE-2022-2613", "CVE-2022-2614", "CVE-2022-2615", "CVE-2022-2616", "CVE-2022-2617", "CVE-2022-2618", "CVE-2022-2619", "CVE-2022-2620", "CVE-2022-2621", "CVE-2022-2622", "CVE-2022-2623", "CVE-2022-2624");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-15 19:13:16 +0000 (Mon, 15 Aug 2022)");
  script_tag(name:"creation_date", value:"2024-03-04 07:13:45 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for chromium (openSUSE-SU-2022:10086-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSEBackportsSLE-15-SP4");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2022:10086-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/43GPO54KYGHLDE7YCWHFLKD7CTXUXDWK");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the openSUSE-SU-2022:10086-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for chromium fixes the following issues:
  Chromium 104.0.5112.79 (boo#1202075)

  * CVE-2022-2603: Use after free in Omnibox

  * CVE-2022-2604: Use after free in Safe Browsing

  * CVE-2022-2605: Out of bounds read in Dawn

  * CVE-2022-2606: Use after free in Managed devices API

  * CVE-2022-2607: Use after free in Tab Strip

  * CVE-2022-2608: Use after free in Overview Mode

  * CVE-2022-2609: Use after free in Nearby Share

  * CVE-2022-2610: Insufficient policy enforcement in Background Fetch

  * CVE-2022-2611: Inappropriate implementation in Fullscreen API

  * CVE-2022-2612: Side-channel information leakage in Keyboard input

  * CVE-2022-2613: Use after free in Input

  * CVE-2022-2614: Use after free in Sign-In Flow

  * CVE-2022-2615: Insufficient policy enforcement in Cookies

  * CVE-2022-2616: Inappropriate implementation in Extensions API

  * CVE-2022-2617: Use after free in Extensions API

  * CVE-2022-2618: Insufficient validation of untrusted input in Internals

  * CVE-2022-2619: Insufficient validation of untrusted input in Settings

  * CVE-2022-2620: Use after free in WebUI

  * CVE-2022-2621: Use after free in Extensions

  * CVE-2022-2622: Insufficient validation of untrusted input in Safe
       Browsing

  * CVE-2022-2623: Use after free in Offline

  * CVE-2022-2624: Heap buffer overflow in PDF

  - Switch back to Clang so that we can use BTI on aarch64

  * Gold is too old - doesn't understand BTI

  * LD crashes on aarch64

  - Re-enable LTO

  - Prepare move to FFmpeg 5 for new channel layout (requires 5.1+)");

  script_tag(name:"affected", value:"'chromium' package(s) on openSUSE Backports SLE-15-SP4.");

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

if(release == "openSUSEBackportsSLE-15-SP4") {

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~104.0.5112.79~bp154.2.20.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~104.0.5112.79~bp154.2.20.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~104.0.5112.79~bp154.2.20.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~104.0.5112.79~bp154.2.20.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
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