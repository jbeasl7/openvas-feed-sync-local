# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833539");
  script_version("2025-03-11T05:38:16+0000");
  script_cve_id("CVE-2023-5480", "CVE-2023-5482", "CVE-2023-5849", "CVE-2023-5850", "CVE-2023-5851", "CVE-2023-5852", "CVE-2023-5853", "CVE-2023-5854", "CVE-2023-5855", "CVE-2023-5856", "CVE-2023-5857", "CVE-2023-5858", "CVE-2023-5859", "CVE-2023-5996");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-15 15:48:42 +0000 (Wed, 15 Nov 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:53:55 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for chromium (openSUSE-SU-2023:0368-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=(openSUSEBackportsSLE-15-SP5|openSUSEBackportsSLE-15-SP4)");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2023:0368-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/KD6QFFZ2QOOLMG34Z7LCSOIITI7H7NZS");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the openSUSE-SU-2023:0368-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for chromium fixes the following issues:

     Chromium 119.0.6045.123 (boo#1216978)

  * CVE-2023-5996: Use after free in WebAudio

     Chromium 119.0.6045.105 (boo#1216783)

  * CVE-2023-5480: Inappropriate implementation in Payments

  * CVE-2023-5482: Insufficient data validation in USB

  * CVE-2023-5849: Integer overflow in USB

  * CVE-2023-5850: Incorrect security UI in Downloads

  * CVE-2023-5851: Inappropriate implementation in Downloads

  * CVE-2023-5852: Use after free in Printing

  * CVE-2023-5853: Incorrect security UI in Downloads

  * CVE-2023-5854: Use after free in Profiles

  * CVE-2023-5855: Use after free in Reading Mode

  * CVE-2023-5856: Use after free in Side Panel

  * CVE-2023-5857: Inappropriate implementation in Downloads

  * CVE-2023-5858: Inappropriate implementation in WebApp Provider

  * CVE-2023-5859: Incorrect security UI in Picture In Picture


     gn was updated to version 0.20231023:

  * many updates to support Chromium 119 build");

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

  if(!isnull(res = isrpmvuln(pkg:"gn", rpm:"gn~0.20231023~bp155.5.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gn-debuginfo", rpm:"gn-debuginfo~0.20231023~bp155.5.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gn-debugsource", rpm:"gn-debugsource~0.20231023~bp155.5.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~119.0.6045.123~bp155.2.55.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromedriver-debuginfo", rpm:"chromedriver-debuginfo~119.0.6045.123~bp155.2.55.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~119.0.6045.123~bp155.2.55.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~119.0.6045.123~bp155.2.55.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gn", rpm:"gn~0.20231023~bp155.5.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gn-debuginfo", rpm:"gn-debuginfo~0.20231023~bp155.5.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gn-debugsource", rpm:"gn-debugsource~0.20231023~bp155.5.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~119.0.6045.123~bp155.2.55.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromedriver-debuginfo", rpm:"chromedriver-debuginfo~119.0.6045.123~bp155.2.55.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~119.0.6045.123~bp155.2.55.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~119.0.6045.123~bp155.2.55.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"gn", rpm:"gn~0.20231023~bp154.3.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gn-debuginfo", rpm:"gn-debuginfo~0.20231023~bp154.3.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gn-debugsource", rpm:"gn-debugsource~0.20231023~bp154.3.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~119.0.6045.123~bp154.2.141.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~119.0.6045.123~bp154.2.141.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gn", rpm:"gn~0.20231023~bp154.3.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gn-debuginfo", rpm:"gn-debuginfo~0.20231023~bp154.3.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gn-debugsource", rpm:"gn-debugsource~0.20231023~bp154.3.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~119.0.6045.123~bp154.2.141.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~119.0.6045.123~bp154.2.141.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
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