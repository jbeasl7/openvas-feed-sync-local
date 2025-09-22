# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833689");
  script_version("2025-03-11T05:38:16+0000");
  script_cve_id("CVE-2021-45341", "CVE-2021-45342");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-01-31 14:54:25 +0000 (Mon, 31 Jan 2022)");
  script_tag(name:"creation_date", value:"2024-03-04 07:22:54 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for librecad (openSUSE-SU-2022:10002-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSEBackportsSLE-15-SP4");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2022:10002-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/6KTACJSABEKBQTYYPFKDEOPJ4JOG4FBE");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'librecad'
  package(s) announced via the openSUSE-SU-2022:10002-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for librecad fixes the following issues:

  - CVE-2021-45341: Fixed a buffer overflow vulnerability in LibreCAD allows
       an attacker to achieve remote code execution via a crafted JWW document
       [boo#1195105]

  - CVE-2021-45342: Fixed a buffer overflow vulnerability in jwwlib in
       LibreCAD allows an attacker to achieve remote code execution via a
       crafted JWW document [boo#1195122]

  - Strip excess blank fields from librecad.desktop:MimeType [boo#1197664]
  Update to 2.2.0-rc3

  * major release

  * DWG imports are more reliable now

  * and a lot more of bugfixes and improvements");

  script_tag(name:"affected", value:"'librecad' package(s) on openSUSE Backports SLE-15-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"libdxfrw-debuginfo", rpm:"libdxfrw-debuginfo~1.0.1+git.20220109~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdxfrw-debugsource", rpm:"libdxfrw-debugsource~1.0.1+git.20220109~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdxfrw-devel", rpm:"libdxfrw-devel~1.0.1+git.20220109~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdxfrw-tools", rpm:"libdxfrw-tools~1.0.1+git.20220109~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdxfrw-tools-debuginfo", rpm:"libdxfrw-tools-debuginfo~1.0.1+git.20220109~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdxfrw1", rpm:"libdxfrw1~1.0.1+git.20220109~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdxfrw1-debuginfo", rpm:"libdxfrw1-debuginfo~1.0.1+git.20220109~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librecad", rpm:"librecad~2.2.0~rc3~bp154.3.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librecad-parts", rpm:"librecad-parts~2.2.0~rc3~bp154.3.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdxfrw-debuginfo", rpm:"libdxfrw-debuginfo~1.0.1+git.20220109~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdxfrw-debugsource", rpm:"libdxfrw-debugsource~1.0.1+git.20220109~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdxfrw-devel", rpm:"libdxfrw-devel~1.0.1+git.20220109~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdxfrw-tools", rpm:"libdxfrw-tools~1.0.1+git.20220109~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdxfrw-tools-debuginfo", rpm:"libdxfrw-tools-debuginfo~1.0.1+git.20220109~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdxfrw1", rpm:"libdxfrw1~1.0.1+git.20220109~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdxfrw1-debuginfo", rpm:"libdxfrw1-debuginfo~1.0.1+git.20220109~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librecad", rpm:"librecad~2.2.0~rc3~bp154.3.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librecad-parts", rpm:"librecad-parts~2.2.0~rc3~bp154.3.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
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