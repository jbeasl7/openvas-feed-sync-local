# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833267");
  script_version("2025-03-11T05:38:16+0000");
  script_cve_id("CVE-2023-0696", "CVE-2023-0697", "CVE-2023-0698", "CVE-2023-0699", "CVE-2023-0700", "CVE-2023-0701", "CVE-2023-0702", "CVE-2023-0703", "CVE-2023-0704", "CVE-2023-0705");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-16 15:16:21 +0000 (Thu, 16 Feb 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:24:48 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for chromium (openSUSE-SU-2023:0045-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSEBackportsSLE-15-SP4");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2023:0045-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/2ZUPRNYY3OQIIYHF4EDZBQMHP655Z7MA");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the openSUSE-SU-2023:0045-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for chromium fixes the following issues:

     Chromium 110.0.5481.77 (boo#1208029):

  * CVE-2023-0696: Type Confusion in V8

  * CVE-2023-0697: Inappropriate implementation in Full screen mode

  * CVE-2023-0698: Out of bounds read in WebRTC

  * CVE-2023-0699: Use after free in GPU

  * CVE-2023-0700: Inappropriate implementation in Download

  * CVE-2023-0701: Heap buffer overflow in WebUI

  * CVE-2023-0702: Type Confusion in Data Transfer

  * CVE-2023-0703: Type Confusion in DevTools

  * CVE-2023-0704: Insufficient policy enforcement in DevTools

  * CVE-2023-0705: Integer overflow in Core

  * Various fixes from internal audits, fuzzing and other initiatives

  - build with bundled libavif");

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

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~110.0.5481.77~bp154.2.67.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~110.0.5481.77~bp154.2.67.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~110.0.5481.77~bp154.2.67.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~110.0.5481.77~bp154.2.67.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
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