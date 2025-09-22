# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.1.2024.0254.2");
  script_cve_id("CVE-2024-6988", "CVE-2024-6989", "CVE-2024-6990", "CVE-2024-6991", "CVE-2024-6992", "CVE-2024-6993", "CVE-2024-6994", "CVE-2024-6995", "CVE-2024-6996", "CVE-2024-6997", "CVE-2024-6998", "CVE-2024-6999", "CVE-2024-7000", "CVE-2024-7001", "CVE-2024-7003", "CVE-2024-7004", "CVE-2024-7005", "CVE-2024-7255", "CVE-2024-7256", "CVE-2024-7532", "CVE-2024-7533", "CVE-2024-7534", "CVE-2024-7535", "CVE-2024-7536", "CVE-2024-7550");
  script_tag(name:"creation_date", value:"2025-02-25 14:26:30 +0000 (Tue, 25 Feb 2025)");
  script_version("2025-02-26T05:38:41+0000");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-12 18:32:08 +0000 (Mon, 12 Aug 2024)");

  script_name("openSUSE Security Advisory (openSUSE-SU-2024:0254-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5|openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2024:0254-2");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/KC4DDO3O7C7P2VVA7A7WIO5RVISNZ3HV/");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228628");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228940");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228941");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228942");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium, gn, rust-bindgen' package(s) announced via the openSUSE-SU-2024:0254-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for chromium, gn, rust-bindgen fixes the following issues:

- Chromium 127.0.6533.119 (boo#1228941)

 * CVE-2024-7532: Out of bounds memory access in ANGLE
 * CVE-2024-7533: Use after free in Sharing
 * CVE-2024-7550: Type Confusion in V8
 * CVE-2024-7534: Heap buffer overflow in Layout
 * CVE-2024-7535: Inappropriate implementation in V8
 * CVE-2024-7536: Use after free in WebAudio

- Chromium 127.0.6533.88 (boo#1228628, boo#1228940, boo#1228942)

 * CVE-2024-6988: Use after free in Downloads
 * CVE-2024-6989: Use after free in Loader
 * CVE-2024-6991: Use after free in Dawn
 * CVE-2024-6992: Out of bounds memory access in ANGLE
 * CVE-2024-6993: Inappropriate implementation in Canvas
 * CVE-2024-6994: Heap buffer overflow in Layout
 * CVE-2024-6995: Inappropriate implementation in Fullscreen
 * CVE-2024-6996: Race in Frames
 * CVE-2024-6997: Use after free in Tabs
 * CVE-2024-6998: Use after free in User Education
 * CVE-2024-6999: Inappropriate implementation in FedCM
 * CVE-2024-7000: Use after free in CSS. Reported by Anonymous
 * CVE-2024-7001: Inappropriate implementation in HTML
 * CVE-2024-7003: Inappropriate implementation in FedCM
 * CVE-2024-7004: Insufficient validation of untrusted input
 in Safe Browsing
 * CVE-2024-7005: Insufficient validation of untrusted input
 in Safe Browsing
 * CVE-2024-6990: Uninitialized Use in Dawn
 * CVE-2024-7255: Out of bounds read in WebTransport
 * CVE-2024-7256: Insufficient data validation in Dawn

gh:

- Update to version 0.20240730:
 * Rust: link_output, depend_output and runtime_outputs for dylibs
 * Add missing reference section to function_toolchain.cc
 * Do not cleanup args.gn imports located in the output directory.
 * Fix expectations in NinjaRustBinaryTargetWriterTest.SwiftModule
 * Do not add native dependencies to the library search path
 * Support linking frameworks and swiftmodules in Rust targets
 * [desc] Silence print() statements when outputing json
 * infra: Move CI/try builds to Ubuntu-22.04
 * [MinGW] Fix mingw building issues
 * [gn] Fix 'link' in the //examples/simple_build/build/toolchain/BUILD.gn
 * [template] Fix 'rule alink_thin' in the //build/build_linux.ninja.template
 * Allow multiple --ide switches
 * [src] Add '#include <limits>' in the //src/base/files/file_enumerator_win.cc
 * Get updates to infra/recipes.py from upstream
 * Revert 'Teach gn to handle systems with > 64 processors'
 * [apple] Rename the code-signing properties of create_bundle
 * Fix a typo in 'gn help refs' output
 * Revert '[bundle] Use 'phony' builtin tool for create_bundle targets'
 * [bundle] Use 'phony' builtin tool for create_bundle targets
 * [ios] Simplify handling of assets catalog
 * [swift] List all outputs as deps of 'source_set' stamp file
 * [swift] Update `gn check ...` to consider the generated header
 * [swift] Set `restat = 1` to swift build rules
 * Fix build with gcc12
 * [label_matches] Add ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'chromium, gn, rust-bindgen' package(s) on openSUSE Leap 15.5, openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~127.0.6533.119~bp156.2.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~127.0.6533.119~bp156.2.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gn", rpm:"gn~0.20240730~bp156.2.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bindgen", rpm:"rust-bindgen~0.69.1~bp156.2.1", rls:"openSUSELeap15.5"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~127.0.6533.119~bp156.2.14.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~127.0.6533.119~bp156.2.14.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gn", rpm:"gn~0.20240730~bp156.2.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bindgen", rpm:"rust-bindgen~0.69.1~bp156.2.1", rls:"openSUSELeap15.6"))) {
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
