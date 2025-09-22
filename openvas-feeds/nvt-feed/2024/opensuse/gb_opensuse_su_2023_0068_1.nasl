# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833611");
  script_version("2025-03-11T05:38:16+0000");
  script_cve_id("CVE-2023-1213", "CVE-2023-1214", "CVE-2023-1215", "CVE-2023-1216", "CVE-2023-1217", "CVE-2023-1218", "CVE-2023-1219", "CVE-2023-1220", "CVE-2023-1221", "CVE-2023-1222", "CVE-2023-1223", "CVE-2023-1224", "CVE-2023-1225", "CVE-2023-1226", "CVE-2023-1227", "CVE-2023-1228", "CVE-2023-1229", "CVE-2023-1230", "CVE-2023-1231", "CVE-2023-1232", "CVE-2023-1233", "CVE-2023-1234", "CVE-2023-1235", "CVE-2023-1236");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-11 02:37:32 +0000 (Sat, 11 Mar 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:25:42 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for chromium (openSUSE-SU-2023:0068-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSEBackportsSLE-15-SP4");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2023:0068-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/E4USJJ6HOC5UIZQM6PHWKEVPCFAFN3DO");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the openSUSE-SU-2023:0068-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for chromium fixes the following issues:

     Chromium 111.0.5563.64

  * New View Transitions API

  * CSS Color Level 4

  * New developer tools in style panel for color functionality

  * CSS added trigonometric functions, additional root font units and
       extended the n-th child pseudo selector.

  * previousslide and nextslide actions are now part of the Media Session API

  * A number of security fixes (boo#1209040)

  * CVE-2023-1213: Use after free in Swiftshader

  * CVE-2023-1214: Type Confusion in V8

  * CVE-2023-1215: Type Confusion in CSS

  * CVE-2023-1216: Use after free in DevTools

  * CVE-2023-1217: Stack buffer overflow in Crash reporting

  * CVE-2023-1218: Use after free in WebRTC

  * CVE-2023-1219: Heap buffer overflow in Metrics

  * CVE-2023-1220: Heap buffer overflow in UMA

  * CVE-2023-1221: Insufficient policy enforcement in Extensions API

  * CVE-2023-1222: Heap buffer overflow in Web Audio API

  * CVE-2023-1223: Insufficient policy enforcement in Autofill

  * CVE-2023-1224: Insufficient policy enforcement in Web Payments API

  * CVE-2023-1225: Insufficient policy enforcement in Navigation

  * CVE-2023-1226: Insufficient policy enforcement in Web Payments API

  * CVE-2023-1227: Use after free in Core

  * CVE-2023-1228: Insufficient policy enforcement in Intents

  * CVE-2023-1229: Inappropriate implementation in Permission prompts

  * CVE-2023-1230: Inappropriate implementation in WebApp Installs

  * CVE-2023-1231: Inappropriate implementation in Autofill

  * CVE-2023-1232: Insufficient policy enforcement in Resource Timing

  * CVE-2023-1233: Insufficient policy enforcement in Resource Timing

  * CVE-2023-1234: Inappropriate implementation in Intents

  * CVE-2023-1235: Type Confusion in DevTools

  * CVE-2023-1236: Inappropriate implementation in Internals");

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

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~111.0.5563.64~bp154.2.73.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~111.0.5563.64~bp154.2.73.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~111.0.5563.64~bp154.2.73.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~111.0.5563.64~bp154.2.73.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
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