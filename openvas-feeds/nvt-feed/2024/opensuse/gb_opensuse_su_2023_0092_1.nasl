# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833088");
  script_version("2025-03-11T05:38:16+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2023-1810", "CVE-2023-1811", "CVE-2023-1812", "CVE-2023-1813", "CVE-2023-1814", "CVE-2023-1815", "CVE-2023-1816", "CVE-2023-1817", "CVE-2023-1818", "CVE-2023-1819", "CVE-2023-1820", "CVE-2023-1821", "CVE-2023-1822", "CVE-2023-1823", "CVE-2023-2033");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-18 12:50:51 +0000 (Tue, 18 Apr 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:59:40 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for chromium (openSUSE-SU-2023:0092-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSEBackportsSLE-15-SP4");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2023:0092-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/BRCY3MMGSLE74IM7LN5E42APXAOQ5ZQG");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the openSUSE-SU-2023:0092-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for chromium fixes the following issues:

  - Chromium 112.0.5615.121:

  * CVE-2023-2033: Type Confusion in V8 (boo#1210478)

  - Chromium 112.0.5615.49

  * CSS now supports nesting rules.

  * The algorithm to set the initial focus on  dialog  elements was
         updated.

  * No-op fetch() handlers on service workers are skipped from now on to
         make navigations faster

  * The setter for document.domain is now deprecated.

  * The recorder in devtools can now record with pierce selectors.

  * Security fixes (boo#1210126):

  * CVE-2023-1810: Heap buffer overflow in Visuals

  * CVE-2023-1811: Use after free in Frames

  * CVE-2023-1812: Out of bounds memory access in DOM Bindings

  * CVE-2023-1813: Inappropriate implementation in Extensions

  * CVE-2023-1814: Insufficient validation of untrusted input in Safe
         Browsing

  * CVE-2023-1815: Use after free in Networking APIs

  * CVE-2023-1816: Incorrect security UI in Picture In Picture

  * CVE-2023-1817: Insufficient policy enforcement in Intents

  * CVE-2023-1818: Use after free in Vulkan

  * CVE-2023-1819: Out of bounds read in Accessibility

  * CVE-2023-1820: Heap buffer overflow in Browser History

  * CVE-2023-1821: Inappropriate implementation in WebShare

  * CVE-2023-1822: Incorrect security UI in Navigation

  * CVE-2023-1823: Inappropriate implementation in FedCM

  - Chromium 111.0.5563.147:

  * nth-child() validation performance regression for SAP apps");

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

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~112.0.5615.121~bp154.2.79.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~112.0.5615.121~bp154.2.79.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~112.0.5615.121~bp154.2.79.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~112.0.5615.121~bp154.2.79.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
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