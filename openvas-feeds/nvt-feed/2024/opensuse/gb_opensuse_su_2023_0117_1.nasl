# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833545");
  script_version("2025-03-11T05:38:16+0000");
  script_cve_id("CVE-2023-2459", "CVE-2023-2460", "CVE-2023-2461", "CVE-2023-2462", "CVE-2023-2463", "CVE-2023-2464", "CVE-2023-2465", "CVE-2023-2466", "CVE-2023-2467", "CVE-2023-2468", "CVE-2023-2721", "CVE-2023-2722", "CVE-2023-2723", "CVE-2023-2724", "CVE-2023-2725", "CVE-2023-2726");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-25 14:54:09 +0000 (Thu, 25 May 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:59:16 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for chromium (openSUSE-SU-2023:0117-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSEBackportsSLE-15-SP4");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2023:0117-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/O7WSJFJTBCMXOOKGPURTAJETTJFNN6NP");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the openSUSE-SU-2023:0117-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for chromium fixes the following issues:

  - build with llvm15 on Leap

  - Chromium 113.0.5672.126 (boo#1211442):

  * CVE-2023-2721: Use after free in Navigation

  * CVE-2023-2722: Use after free in Autofill UI

  * CVE-2023-2723: Use after free in DevTools

  * CVE-2023-2724: Type Confusion in V8

  * CVE-2023-2725: Use after free in Guest View

  * CVE-2023-2726: Inappropriate implementation in WebApp Installs

  * Various fixes from internal audits, fuzzing and other initiatives

  - Chromium 113.0.5672.92 (boo#1211211)

  - Multiple security fixes (boo#1211036):

  * CVE-2023-2459: Inappropriate implementation in Prompts

  * CVE-2023-2460: Insufficient validation of untrusted input in Extensions

  * CVE-2023-2461: Use after free in OS Inputs

  * CVE-2023-2462: Inappropriate implementation in Prompts

  * CVE-2023-2463: Inappropriate implementation in Full Screen Mode

  * CVE-2023-2464: Inappropriate implementation in PictureInPicture

  * CVE-2023-2465: Inappropriate implementation in CORS

  * CVE-2023-2466: Inappropriate implementation in Prompts

  * CVE-2023-2467: Inappropriate implementation in Prompts

  * CVE-2023-2468: Inappropriate implementation in PictureInPicture");

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

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~113.0.5672.126~bp154.2.87.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~113.0.5672.126~bp154.2.87.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~113.0.5672.126~bp154.2.87.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~113.0.5672.126~bp154.2.87.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
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