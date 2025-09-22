# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856143");
  script_cve_id("CVE-2024-2625", "CVE-2024-2626", "CVE-2024-2627", "CVE-2024-2628", "CVE-2024-2883", "CVE-2024-2885", "CVE-2024-2886", "CVE-2024-2887", "CVE-2024-3156", "CVE-2024-3157", "CVE-2024-3158", "CVE-2024-3159", "CVE-2024-3515", "CVE-2024-3516", "CVE-2024-3832", "CVE-2024-3833", "CVE-2024-3834", "CVE-2024-3837", "CVE-2024-3838", "CVE-2024-3839", "CVE-2024-3840", "CVE-2024-3841", "CVE-2024-3843", "CVE-2024-3844", "CVE-2024-3845", "CVE-2024-3846", "CVE-2024-3847", "CVE-2024-4058", "CVE-2024-4059", "CVE-2024-4060", "CVE-2024-4331", "CVE-2024-4368", "CVE-2024-4558", "CVE-2024-4559", "CVE-2024-4671");
  script_tag(name:"creation_date", value:"2024-05-14 01:00:23 +0000 (Tue, 14 May 2024)");
  script_version("2025-02-26T05:38:40+0000");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:40 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-05-16 20:27:10 +0000 (Thu, 16 May 2024)");

  script_name("openSUSE Security Advisory (openSUSE-SU-2024:0123-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2024:0123-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/2S7S4HVABEMIRHPQD4H3O6EA36PLCUCI/");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221732");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222035");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222260");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222707");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222958");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223845");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223846");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224045");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium' package(s) announced via the openSUSE-SU-2024:0123-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for chromium fixes the following issues:

- Chromium 124.0.6367.201
 * CVE-2024-4671: Use after free in Visuals

- Chromium 124.0.6367.155 (boo#1224045)
 * CVE-2024-4558: Use after free in ANGLE
 * CVE-2024-4559: Heap buffer overflow in WebAudio

- Chromium 124.0.6367.118 (boo#1223846)
 * CVE-2024-4331: Use after free in Picture In Picture
 * CVE-2024-4368: Use after free in Dawn

- Chromium 124.0.6367.78 (boo#1223845)
 * CVE-2024-4058: Type Confusion in ANGLE
 * CVE-2024-4059: Out of bounds read in V8 API
 * CVE-2024-4060: Use after free in Dawn

- Chromium 124.0.6367.60 (boo#1222958)
 * CVE-2024-3832: Object corruption in V8.
 * CVE-2024-3833: Object corruption in WebAssembly.
 * CVE-2024-3834: Use after free in Downloads. Reported by ChaobinZhang
 * CVE-2024-3837: Use after free in QUIC.
 * CVE-2024-3838: Inappropriate implementation in Autofill.
 * CVE-2024-3839: Out of bounds read in Fonts.
 * CVE-2024-3840: Insufficient policy enforcement in Site Isolation.
 * CVE-2024-3841: Insufficient data validation in Browser Switcher.
 * CVE-2024-3843: Insufficient data validation in Downloads.
 * CVE-2024-3844: Inappropriate implementation in Extensions.
 * CVE-2024-3845: Inappropriate implementation in Network.
 * CVE-2024-3846: Inappropriate implementation in Prompts.
 * CVE-2024-3847: Insufficient policy enforcement in WebUI.

- Chromium 123.0.6312.122 (boo#1222707)
 * CVE-2024-3157: Out of bounds write in Compositing
 * CVE-2024-3516: Heap buffer overflow in ANGLE
 * CVE-2024-3515: Use after free in Dawn

- Chromium 123.0.6312.105 (boo#1222260)
 * CVE-2024-3156: Inappropriate implementation in V8
 * CVE-2024-3158: Use after free in Bookmarks
 * CVE-2024-3159: Out of bounds memory access in V8

- Chromium 123.0.6312.86 (boo#1222035)
 * CVE-2024-2883: Use after free in ANGLE
 * CVE-2024-2885: Use after free in Dawn
 * CVE-2024-2886: Use after free in WebCodecs
 * CVE-2024-2887: Type Confusion in WebAssembly

- Chromium 123.0.6312.58 (boo#1221732)
 * CVE-2024-2625: Object lifecycle issue in V8
 * CVE-2024-2626: Out of bounds read in Swiftshader
 * CVE-2024-2627: Use after free in Canvas
 * CVE-2024-2628: Inappropriate implementation in Downloads");

  script_tag(name:"affected", value:"'chromium' package(s) on openSUSE Leap 15.5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

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

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~124.0.6367.201~bp155.2.78.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~124.0.6367.201~bp155.2.78.1", rls:"openSUSELeap15.5"))) {
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
