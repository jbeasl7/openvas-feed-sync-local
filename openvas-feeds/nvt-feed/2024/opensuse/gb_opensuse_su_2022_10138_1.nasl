# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833422");
  script_version("2025-03-11T05:38:16+0000");
  script_cve_id("CVE-2022-3201", "CVE-2022-3304", "CVE-2022-3305", "CVE-2022-3306", "CVE-2022-3307", "CVE-2022-3308", "CVE-2022-3309", "CVE-2022-3310", "CVE-2022-3311", "CVE-2022-3312", "CVE-2022-3313", "CVE-2022-3314", "CVE-2022-3315", "CVE-2022-3316", "CVE-2022-3317", "CVE-2022-3318", "CVE-2022-3370", "CVE-2022-3373");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-01 18:20:49 +0000 (Tue, 01 Nov 2022)");
  script_tag(name:"creation_date", value:"2024-03-04 07:58:58 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for chromium (openSUSE-SU-2022:10138-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSEBackportsSLE-15-SP4");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2022:10138-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/YZBW4AE4VW4MIHPWQLMJEIBGACVXWAFW");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the openSUSE-SU-2022:10138-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for chromium fixes the following issues:
  Chromium 106.0.5249.91 (boo#1203808):

  * CVE-2022-3370: Use after free in Custom Elements

  * CVE-2022-3373: Out of bounds write in V8
  includes changes from 106.0.5249.61:

  * CVE-2022-3304: Use after free in CSS

  * CVE-2022-3201: Insufficient validation of untrusted input in Developer
       Tools

  * CVE-2022-3305: Use after free in Survey

  * CVE-2022-3306: Use after free in Survey

  * CVE-2022-3307: Use after free in Media

  * CVE-2022-3308: Insufficient policy enforcement in Developer Tools

  * CVE-2022-3309: Use after free in Assistant

  * CVE-2022-3310: Insufficient policy enforcement in Custom Tabs

  * CVE-2022-3311: Use after free in Import

  * CVE-2022-3312: Insufficient validation of untrusted input in VPN

  * CVE-2022-3313: Incorrect security UI in Full Screen

  * CVE-2022-3314: Use after free in Logging

  * CVE-2022-3315: Type confusion in Blink

  * CVE-2022-3316: Insufficient validation of untrusted input in Safe
       Browsing

  * CVE-2022-3317: Insufficient validation of untrusted input in Intents

  * CVE-2022-3318: Use after free in ChromeOS Notifications");

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

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~106.0.5249.91~bp154.2.32.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~106.0.5249.91~bp154.2.32.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~106.0.5249.91~bp154.2.32.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~106.0.5249.91~bp154.2.32.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
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