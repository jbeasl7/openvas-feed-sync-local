# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833428");
  script_version("2025-03-11T05:38:16+0000");
  script_cve_id("CVE-2023-3727", "CVE-2023-3728", "CVE-2023-3730", "CVE-2023-3732", "CVE-2023-3733", "CVE-2023-3734", "CVE-2023-3735", "CVE-2023-3736", "CVE-2023-3737", "CVE-2023-3738", "CVE-2023-3740");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-04 03:52:37 +0000 (Fri, 04 Aug 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:24:36 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for chromium (openSUSE-SU-2023:0193-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=(openSUSEBackportsSLE-15-SP5|openSUSEBackportsSLE-15-SP4)");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2023:0193-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/7YFWX4SWCVBUO47OZ3HWZCBOE3G7ZGAE");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the openSUSE-SU-2023:0193-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for chromium fixes the following issues:

     Chromium 115.0.5790.102:

  * stability fix

     Chromium 115.0.5790.98:

  * Security: The Storage, Service Worker, and Communication APIs are now
       partitioned in third-party contexts to prevent certain types of
       side-channel cross-site tracking

  * HTTPS: Automatically and optimistically upgrade all main-frame
       navigations to HTTPS, with fast fallback to HTTP.

  * CSS: accept multiple values of the display property

  * CSS: support boolean context style container queries

  * CSS: support scroll-driven animations

  * Increase the maximum size of a WebAssembly.Module() on the main thread
       to 8 MB

  * FedCM: Support credential management mediation requirements for auto
       re-authentication

  * Deprecate the document.domain setter

  * Deprecate mutation events

  * Security fixes (boo#1213462):

  - CVE-2023-3727: Use after free in WebRTC

  - CVE-2023-3728: Use after free in WebRTC

  - CVE-2023-3730: Use after free in Tab Groups

  - CVE-2023-3732: Out of bounds memory access in Mojo

  - CVE-2023-3733: Inappropriate implementation in WebApp Installs

  - CVE-2023-3734: Inappropriate implementation in Picture In Picture

  - CVE-2023-3735: Inappropriate implementation in Web API Permission
         Prompts

  - CVE-2023-3736: Inappropriate implementation in Custom Tabs

  - CVE-2023-3737: Inappropriate implementation in Notifications

  - CVE-2023-3738: Inappropriate implementation in Autofill

  - CVE-2023-3740: Insufficient validation of untrusted input in Themes

  - Various fixes from internal audits, fuzzing and other initiatives");

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

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~115.0.5790.102~bp155.2.13.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromedriver-debuginfo", rpm:"chromedriver-debuginfo~115.0.5790.102~bp155.2.13.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~115.0.5790.102~bp155.2.13.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~115.0.5790.102~bp155.2.13.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~115.0.5790.102~bp155.2.13.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromedriver-debuginfo", rpm:"chromedriver-debuginfo~115.0.5790.102~bp155.2.13.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~115.0.5790.102~bp155.2.13.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~115.0.5790.102~bp155.2.13.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~115.0.5790.102~bp154.2.99.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~115.0.5790.102~bp154.2.99.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~115.0.5790.102~bp154.2.99.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~115.0.5790.102~bp154.2.99.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
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