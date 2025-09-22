# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833395");
  script_version("2025-03-11T05:38:16+0000");
  script_cve_id("CVE-2023-2312", "CVE-2023-4349", "CVE-2023-4350", "CVE-2023-4351", "CVE-2023-4352", "CVE-2023-4353", "CVE-2023-4354", "CVE-2023-4355", "CVE-2023-4356", "CVE-2023-4357", "CVE-2023-4358", "CVE-2023-4359", "CVE-2023-4360", "CVE-2023-4361", "CVE-2023-4362", "CVE-2023-4363", "CVE-2023-4364", "CVE-2023-4365", "CVE-2023-4366", "CVE-2023-4367", "CVE-2023-4368");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-22 13:42:31 +0000 (Tue, 22 Aug 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:18:48 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for chromium (openSUSE-SU-2023:0234-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=(openSUSEBackportsSLE-15-SP5|openSUSEBackportsSLE-15-SP4)");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2023:0234-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/BHGOO7OFVF75LWZYDKQO5H6ZBGN5JVTX");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the openSUSE-SU-2023:0234-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for chromium fixes the following issues:

     Chromium 116.0.5845.96

  * New CSS features: Motion Path, and 'display' and 'content-visibility'
       animations

  * Web APIs: AbortSignal.any(), BYOB support for Fetch, Back/ forward cache
       NotRestoredReason API, Document Picture-in- Picture, Expanded Wildcards
       in Permissions Policy Origins, FedCM bundle: Login Hint API, User Info
       API, and RP Context API, Non-composed Mouse and Pointer enter/leave
       events, Remove document.open sandbox inheritance, Report Critical-CH
       caused restart in NavigationTiming

     This update fixes a number of security issues (boo#1214301):

  * CVE-2023-2312: Use after free in Offline

  * CVE-2023-4349: Use after free in Device Trust Connectors

  * CVE-2023-4350: Inappropriate implementation in Fullscreen

  * CVE-2023-4351: Use after free in Network

  * CVE-2023-4352: Type Confusion in V8

  * CVE-2023-4353: Heap buffer overflow in ANGLE

  * CVE-2023-4354: Heap buffer overflow in Skia

  * CVE-2023-4355: Out of bounds memory access in V8

  * CVE-2023-4356: Use after free in Audio

  * CVE-2023-4357: Insufficient validation of untrusted input in XML

  * CVE-2023-4358: Use after free in DNS

  * CVE-2023-4359: Inappropriate implementation in App Launcher

  * CVE-2023-4360: Inappropriate implementation in Color

  * CVE-2023-4361: Inappropriate implementation in Autofill

  * CVE-2023-4362: Heap buffer overflow in Mojom IDL

  * CVE-2023-4363: Inappropriate implementation in WebShare

  * CVE-2023-4364: Inappropriate implementation in Permission Prompts

  * CVE-2023-4365: Inappropriate implementation in Fullscreen

  * CVE-2023-4366: Use after free in Extensions

  * CVE-2023-4367: Insufficient policy enforcement in Extensions API

  * CVE-2023-4368: Insufficient policy enforcement in Extensions API

  - Fix crash with extensions (boo#1214003)");

  script_tag(name:"affected", value:"'chromium' package(s) on openSUSE Backports SLE-15-SP4, openSUSE Backports SLE-15-SP5.");

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

if(release == "openSUSEBackportsSLE-15-SP5") {

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~116.0.5845.96~bp155.2.19.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromedriver-debuginfo", rpm:"chromedriver-debuginfo~116.0.5845.96~bp155.2.19.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~116.0.5845.96~bp155.2.19.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~116.0.5845.96~bp155.2.19.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~116.0.5845.96~bp155.2.19.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromedriver-debuginfo", rpm:"chromedriver-debuginfo~116.0.5845.96~bp155.2.19.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~116.0.5845.96~bp155.2.19.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~116.0.5845.96~bp155.2.19.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSEBackportsSLE-15-SP4") {

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~116.0.5845.96~bp154.2.105.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~116.0.5845.96~bp154.2.105.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~116.0.5845.96~bp154.2.105.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~116.0.5845.96~bp154.2.105.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
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