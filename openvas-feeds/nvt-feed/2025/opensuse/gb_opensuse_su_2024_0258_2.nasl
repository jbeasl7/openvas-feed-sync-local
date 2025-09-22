# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.1.2024.0258.2");
  script_cve_id("CVE-2024-7964", "CVE-2024-7965", "CVE-2024-7966", "CVE-2024-7967", "CVE-2024-7968", "CVE-2024-7969", "CVE-2024-7971", "CVE-2024-7972", "CVE-2024-7973", "CVE-2024-7974", "CVE-2024-7975", "CVE-2024-7976", "CVE-2024-7977", "CVE-2024-7978", "CVE-2024-7979", "CVE-2024-7980", "CVE-2024-7981", "CVE-2024-8033", "CVE-2024-8034", "CVE-2024-8035");
  script_tag(name:"creation_date", value:"2025-02-25 14:26:30 +0000 (Tue, 25 Feb 2025)");
  script_version("2025-02-26T05:38:41+0000");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-11-27 17:21:35 +0000 (Wed, 27 Nov 2024)");

  script_name("openSUSE Security Advisory (openSUSE-SU-2024:0258-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5|openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2024:0258-2");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/G5G3DFUIZH3E3T5UIPSI3LSGCI5KE3NF/");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229426");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229591");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium' package(s) announced via the openSUSE-SU-2024:0258-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for chromium fixes the following issues:

- Chromium 128.0.6613.84 (boo#1229591)
 * CVE-2024-7964: Use after free in Passwords
 * CVE-2024-7965: Inappropriate implementation in V8
 * CVE-2024-7966: Out of bounds memory access in Skia
 * CVE-2024-7967: Heap buffer overflow in Fonts
 * CVE-2024-7968: Use after free in Autofill
 * CVE-2024-7969: Type Confusion in V8
 * CVE-2024-7971: Type confusion in V8
 * CVE-2024-7972: Inappropriate implementation in V8
 * CVE-2024-7973: Heap buffer overflow in PDFium
 * CVE-2024-7974: Insufficient data validation in V8 API
 * CVE-2024-7975: Inappropriate implementation in Permissions
 * CVE-2024-7976: Inappropriate implementation in FedCM
 * CVE-2024-7977: Insufficient data validation in Installer
 * CVE-2024-7978: Insufficient policy enforcement in Data Transfer
 * CVE-2024-7979: Insufficient data validation in Installer
 * CVE-2024-7980: Insufficient data validation in Installer
 * CVE-2024-7981: Inappropriate implementation in Views
 * CVE-2024-8033: Inappropriate implementation in WebApp Installs
 * CVE-2024-8034: Inappropriate implementation in Custom Tabs
 * CVE-2024-8035: Inappropriate implementation in Extensions
 * Various fixes from internal audits, fuzzing and other initiatives");

  script_tag(name:"affected", value:"'chromium' package(s) on openSUSE Leap 15.5, openSUSE Leap 15.6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

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

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~128.0.6613.84~bp156.2.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~128.0.6613.84~bp156.2.17.1", rls:"openSUSELeap15.5"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~128.0.6613.84~bp156.2.17.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~128.0.6613.84~bp156.2.17.1", rls:"openSUSELeap15.6"))) {
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
