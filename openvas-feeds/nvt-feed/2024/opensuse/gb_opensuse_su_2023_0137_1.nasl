# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833447");
  script_version("2025-03-11T05:38:16+0000");
  script_cve_id("CVE-2016-8605", "CVE-2020-17354");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-25 16:52:41 +0000 (Tue, 25 Apr 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 08:06:16 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for guile1, lilypond (openSUSE-SU-2023:0137-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSEBackportsSLE-15-SP4");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2023:0137-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/ROLJCNPWZ2G4IQWP7NQKXNBT2QR32K2A");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'guile1, lilypond'
  package(s) announced via the openSUSE-SU-2023:0137-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for guile1, lilypond fixes the following issues:

     guile1:

  - Add service file to download release from git excluding the directory
       with commercial non free files.

  - Update to version 2.2.6 to enable lilypond to be updated to 2.24.1 to
       fix boo#1210502 and CVE-2020-17354.

     lilypond:

  - Update to version lilypond-2.24.1 to fix boo#1210502 - CVE-2020-17354:
       lilypond: Lilypond allows attackers to bypass the -dsafe protection
       mechanism.");

  script_tag(name:"affected", value:"'guile1, lilypond' package(s) on openSUSE Backports SLE-15-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"guile1", rpm:"guile1~2.2.6~bp154.3.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"guile1-modules-2_2", rpm:"guile1-modules-2_2~2.2.6~bp154.3.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libguile-2_2-1", rpm:"libguile-2_2-1~2.2.6~bp154.3.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libguile1-devel", rpm:"libguile1-devel~2.2.6~bp154.3.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lilypond", rpm:"lilypond~2.24.1~bp154.2.3.2", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lilypond-debuginfo", rpm:"lilypond-debuginfo~2.24.1~bp154.2.3.2", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lilypond-debugsource", rpm:"lilypond-debugsource~2.24.1~bp154.2.3.2", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lilypond-doc", rpm:"lilypond-doc~2.24.1~bp154.2.3.2", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lilypond-doc-cs", rpm:"lilypond-doc-cs~2.24.1~bp154.2.3.2", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lilypond-doc-de", rpm:"lilypond-doc-de~2.24.1~bp154.2.3.2", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lilypond-doc-es", rpm:"lilypond-doc-es~2.24.1~bp154.2.3.2", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lilypond-doc-fr", rpm:"lilypond-doc-fr~2.24.1~bp154.2.3.2", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lilypond-doc-hu", rpm:"lilypond-doc-hu~2.24.1~bp154.2.3.2", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lilypond-doc-it", rpm:"lilypond-doc-it~2.24.1~bp154.2.3.2", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lilypond-doc-ja", rpm:"lilypond-doc-ja~2.24.1~bp154.2.3.2", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lilypond-doc-nl", rpm:"lilypond-doc-nl~2.24.1~bp154.2.3.2", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lilypond-doc-zh", rpm:"lilypond-doc-zh~2.24.1~bp154.2.3.2", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lilypond-emmentaler-fonts", rpm:"lilypond-emmentaler-fonts~2.24.1~bp154.2.3.2", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lilypond-fonts-common", rpm:"lilypond-fonts-common~2.24.1~bp154.2.3.2", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"guile1", rpm:"guile1~2.2.6~bp154.3.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"guile1-modules-2_2", rpm:"guile1-modules-2_2~2.2.6~bp154.3.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libguile-2_2-1", rpm:"libguile-2_2-1~2.2.6~bp154.3.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libguile1-devel", rpm:"libguile1-devel~2.2.6~bp154.3.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lilypond", rpm:"lilypond~2.24.1~bp154.2.3.2", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lilypond-debuginfo", rpm:"lilypond-debuginfo~2.24.1~bp154.2.3.2", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lilypond-debugsource", rpm:"lilypond-debugsource~2.24.1~bp154.2.3.2", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lilypond-doc", rpm:"lilypond-doc~2.24.1~bp154.2.3.2", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lilypond-doc-cs", rpm:"lilypond-doc-cs~2.24.1~bp154.2.3.2", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lilypond-doc-de", rpm:"lilypond-doc-de~2.24.1~bp154.2.3.2", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lilypond-doc-es", rpm:"lilypond-doc-es~2.24.1~bp154.2.3.2", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lilypond-doc-fr", rpm:"lilypond-doc-fr~2.24.1~bp154.2.3.2", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lilypond-doc-hu", rpm:"lilypond-doc-hu~2.24.1~bp154.2.3.2", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lilypond-doc-it", rpm:"lilypond-doc-it~2.24.1~bp154.2.3.2", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lilypond-doc-ja", rpm:"lilypond-doc-ja~2.24.1~bp154.2.3.2", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lilypond-doc-nl", rpm:"lilypond-doc-nl~2.24.1~bp154.2.3.2", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lilypond-doc-zh", rpm:"lilypond-doc-zh~2.24.1~bp154.2.3.2", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lilypond-emmentaler-fonts", rpm:"lilypond-emmentaler-fonts~2.24.1~bp154.2.3.2", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lilypond-fonts-common", rpm:"lilypond-fonts-common~2.24.1~bp154.2.3.2", rls:"openSUSEBackportsSLE-15-SP4"))) {
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