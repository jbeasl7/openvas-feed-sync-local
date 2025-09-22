# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833239");
  script_version("2025-03-11T05:38:16+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2022-3038", "CVE-2022-3039", "CVE-2022-3040", "CVE-2022-3041", "CVE-2022-3042", "CVE-2022-3043", "CVE-2022-3044", "CVE-2022-3045", "CVE-2022-3046", "CVE-2022-3047", "CVE-2022-3048", "CVE-2022-3049", "CVE-2022-3050", "CVE-2022-3051", "CVE-2022-3052", "CVE-2022-3053", "CVE-2022-3054", "CVE-2022-3055", "CVE-2022-3056", "CVE-2022-3057", "CVE-2022-3058", "CVE-2022-3071", "CVE-2022-3075");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-30 18:47:00 +0000 (Fri, 30 Sep 2022)");
  script_tag(name:"creation_date", value:"2024-03-04 07:45:46 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for chromium (openSUSE-SU-2022:10119-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSEBackportsSLE-15-SP4");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2022:10119-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/GAVZ7A2NRXHLI7C5TFF7GQHYKEGQIQRR");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the openSUSE-SU-2022:10119-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for chromium fixes the following issues:
  Chromium 105.0.5195.102 (boo#1203102):

  * CVE-2022-3075: Insufficient data validation in Mojo
  Chromium 105.0.5195.52 (boo#1202964):

  * CVE-2022-3038: Use after free in Network Service

  * CVE-2022-3039: Use after free in WebSQL

  * CVE-2022-3040: Use after free in Layout

  * CVE-2022-3041: Use after free in WebSQL

  * CVE-2022-3042: Use after free in PhoneHub

  * CVE-2022-3043: Heap buffer overflow in Screen Capture

  * CVE-2022-3044: Inappropriate implementation in Site Isolation

  * CVE-2022-3045: Insufficient validation of untrusted input in V8

  * CVE-2022-3046: Use after free in Browser Tag

  * CVE-2022-3071: Use after free in Tab Strip

  * CVE-2022-3047: Insufficient policy enforcement in Extensions API

  * CVE-2022-3048: Inappropriate implementation in Chrome OS lockscreen

  * CVE-2022-3049: Use after free in SplitScreen

  * CVE-2022-3050: Heap buffer overflow in WebUI

  * CVE-2022-3051: Heap buffer overflow in Exosphere

  * CVE-2022-3052: Heap buffer overflow in Window Manager

  * CVE-2022-3053: Inappropriate implementation in Pointer Lock

  * CVE-2022-3054: Insufficient policy enforcement in DevTools

  * CVE-2022-3055: Use after free in Passwords

  * CVE-2022-3056: Insufficient policy enforcement in Content Security Policy

  * CVE-2022-3057: Inappropriate implementation in iframe Sandbox

  * CVE-2022-3058: Use after free in Sign-In Flow

  - Update chromium-symbolic.svg: this fixes boo#1202403.

  - Fix quoting in chrome-wrapper, don't put cwd on LD_LIBRARY_PATH");

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

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~105.0.5195.102~bp154.2.26.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~105.0.5195.102~bp154.2.26.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~105.0.5195.102~bp154.2.26.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~105.0.5195.102~bp154.2.26.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
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