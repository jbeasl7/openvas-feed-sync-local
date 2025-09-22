# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.0300.1");
  script_cve_id("CVE-2017-1000376");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:48 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-05 17:58:37 +0000 (Wed, 05 Jul 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:0300-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP3|SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:0300-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20180300-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1039513");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1044016");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1045091");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1059075");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1074621");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/938159");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/977654");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/999596");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2018-January/007862.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gcc43' package(s) announced via the SUSE-SU-2018:0300-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for gcc43 fixes the following issues:

Security issue fixed:

- CVE-2017-1000376: Don't request excutable stack from libffi. [bnc#1045091]

New features:

- Add support for retpolines to mitigate the Spectre Variant 2 attack. [bnc#1074621]
- Add support for zero-sized VLAs and allocas with -fstack-clash-protection. [bnc#1059075]
- Add support for -fstack-clash-protection to mitigate the Stack Clash attack. [bnc#1039513]

Non security bugs fixed:

- Fixed build of 32bit libgcov.a with LFS support. [bsc#1044016]
- Fixed issue with libstdc++ functional when an exception is thrown during construction. [bsc#999596]
- Fixed issue with using gcov and #pragma pack. [bsc#977654]
- Fixed ICE compiling AFS modules for the s390x kernel. [bsc#938159]
- Backport large file support from GCC 4.6.");

  script_tag(name:"affected", value:"'gcc43' package(s) on SUSE Linux Enterprise Server 11-SP3, SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server for SAP Applications 11-SP4.");

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

if(release == "SLES11.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"cpp43", rpm:"cpp43~4.3.4_20091019~37.3.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc43-32bit", rpm:"gcc43-32bit~4.3.4_20091019~37.3.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc43", rpm:"gcc43~4.3.4_20091019~37.3.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc43-c++", rpm:"gcc43-c++~4.3.4_20091019~37.3.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc43-fortran-32bit", rpm:"gcc43-fortran-32bit~4.3.4_20091019~37.3.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc43-fortran", rpm:"gcc43-fortran~4.3.4_20091019~37.3.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc43-info", rpm:"gcc43-info~4.3.4_20091019~37.3.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc43-locale", rpm:"gcc43-locale~4.3.4_20091019~37.3.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++43-devel-32bit", rpm:"libstdc++43-devel-32bit~4.3.4_20091019~37.3.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++43-devel", rpm:"libstdc++43-devel~4.3.4_20091019~37.3.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"cpp43", rpm:"cpp43~4.3.4_20091019~37.3.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc43-32bit", rpm:"gcc43-32bit~4.3.4_20091019~37.3.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc43", rpm:"gcc43~4.3.4_20091019~37.3.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc43-c++", rpm:"gcc43-c++~4.3.4_20091019~37.3.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc43-info", rpm:"gcc43-info~4.3.4_20091019~37.3.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc43-locale", rpm:"gcc43-locale~4.3.4_20091019~37.3.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++43-devel-32bit", rpm:"libstdc++43-devel-32bit~4.3.4_20091019~37.3.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++43-devel", rpm:"libstdc++43-devel~4.3.4_20091019~37.3.1", rls:"SLES11.0SP4"))) {
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
