# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.1.2024.0204.1");
  script_cve_id("CVE-2024-5830", "CVE-2024-5831", "CVE-2024-5832", "CVE-2024-5833", "CVE-2024-5834", "CVE-2024-5835", "CVE-2024-5836", "CVE-2024-5837", "CVE-2024-5838", "CVE-2024-5839", "CVE-2024-5840", "CVE-2024-5841", "CVE-2024-5842", "CVE-2024-5843", "CVE-2024-5844", "CVE-2024-5845", "CVE-2024-5846", "CVE-2024-5847", "CVE-2024-6100", "CVE-2024-6101", "CVE-2024-6102", "CVE-2024-6103", "CVE-2024-6290", "CVE-2024-6291", "CVE-2024-6292", "CVE-2024-6293");
  script_tag(name:"creation_date", value:"2025-02-25 14:26:30 +0000 (Tue, 25 Feb 2025)");
  script_version("2025-02-26T05:38:41+0000");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-26 16:02:51 +0000 (Thu, 26 Dec 2024)");

  script_name("openSUSE Security Advisory (openSUSE-SU-2024:0204-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5|openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2024:0204-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/M5T6NMGYYELQHJOU75BSCQDFQVQRR5I7/");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226170");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226205");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226504");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226933");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium' package(s) announced via the openSUSE-SU-2024:0204-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for chromium fixes the following issues:

Chromium 126.0.6478.126 (boo#1226504, boo#1226205, boo#1226933)

 * CVE-2024-6290: Use after free in Dawn
 * CVE-2024-6291: Use after free in Swiftshader
 * CVE-2024-6292: Use after free in Dawn
 * CVE-2024-6293: Use after free in Dawn
 * CVE-2024-6100: Type Confusion in V8
 * CVE-2024-6101: Inappropriate implementation in WebAssembly
 * CVE-2024-6102: Out of bounds memory access in Dawn
 * CVE-2024-6103: Use after free in Dawn
 * CVE-2024-5830: Type Confusion in V8
 * CVE-2024-5831: Use after free in Dawn
 * CVE-2024-5832: Use after free in Dawn
 * CVE-2024-5833: Type Confusion in V8
 * CVE-2024-5834: Inappropriate implementation in Dawn
 * CVE-2024-5835: Heap buffer overflow in Tab Groups
 * CVE-2024-5836: Inappropriate Implementation in DevTools
 * CVE-2024-5837: Type Confusion in V8
 * CVE-2024-5838: Type Confusion in V8
 * CVE-2024-5839: Inappropriate Implementation in Memory Allocator
 * CVE-2024-5840: Policy Bypass in CORS
 * CVE-2024-5841: Use after free in V8
 * CVE-2024-5842: Use after free in Browser UI
 * CVE-2024-5843: Inappropriate implementation in Downloads
 * CVE-2024-5844: Heap buffer overflow in Tab Strip
 * CVE-2024-5845: Use after free in Audio
 * CVE-2024-5846: Use after free in PDFium
 * CVE-2024-5847: Use after free in PDFium

- Amend fix_building_widevinecdm_with_chromium.patch to allow
 Widevine on ARM64 (boo#1226170)");

  script_tag(name:"affected", value:"'chromium' package(s) on openSUSE Leap 15.5, openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~126.0.6478.126~bp156.2.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~126.0.6478.126~bp156.2.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~126.0.6478.126~bp156.2.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~126.0.6478.126~bp156.2.6.1", rls:"openSUSELeap15.6"))) {
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
