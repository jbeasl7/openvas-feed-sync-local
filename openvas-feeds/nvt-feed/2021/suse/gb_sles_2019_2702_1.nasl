# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.2702.1");
  script_cve_id("CVE-2019-14250", "CVE-2019-15847");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:15 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-09-05 20:24:01 +0000 (Thu, 05 Sep 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:2702-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0|SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:2702-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20192702-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gcc7' package(s) announced via the SUSE-SU-2019:2702-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for gcc7 to r275405 fixes the following issues:

Security issues fixed:
CVE-2019-14250: Fixed an integer overflow in binutils (bsc#1142649).

CVE-2019-15847: Fixed an optimization in the POWER9 backend of gcc that
 could reduce the entropy of the random number generator (bsc#1149145).

Non-security issue fixed:
Move Live Patching technology stack from kGraft to upstream klp
 (bsc#1071995, fate#323487).");

  script_tag(name:"affected", value:"'gcc7' package(s) on SUSE Linux Enterprise Module for Basesystem 15, SUSE Linux Enterprise Module for Basesystem 15-SP1, SUSE Linux Enterprise Module for Development Tools 15, SUSE Linux Enterprise Module for Development Tools 15-SP1, SUSE Linux Enterprise Module for Open Buildservice Development Tools 15, SUSE Linux Enterprise Module for Open Buildservice Development Tools 15-SP1.");

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

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"cpp7", rpm:"cpp7~7.4.1+r275405~4.9.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cpp7-debuginfo", rpm:"cpp7-debuginfo~7.4.1+r275405~4.9.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7", rpm:"gcc7~7.4.1+r275405~4.9.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-c++", rpm:"gcc7-c++~7.4.1+r275405~4.9.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-c++-debuginfo", rpm:"gcc7-c++-debuginfo~7.4.1+r275405~4.9.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-debuginfo", rpm:"gcc7-debuginfo~7.4.1+r275405~4.9.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-debugsource", rpm:"gcc7-debugsource~7.4.1+r275405~4.9.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-fortran", rpm:"gcc7-fortran~7.4.1+r275405~4.9.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-fortran-debuginfo", rpm:"gcc7-fortran-debuginfo~7.4.1+r275405~4.9.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasan4", rpm:"libasan4~7.4.1+r275405~4.9.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasan4-debuginfo", rpm:"libasan4-debuginfo~7.4.1+r275405~4.9.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcilkrts5", rpm:"libcilkrts5~7.4.1+r275405~4.9.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcilkrts5-debuginfo", rpm:"libcilkrts5-debuginfo~7.4.1+r275405~4.9.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgfortran4-32bit", rpm:"libgfortran4-32bit~7.4.1+r275405~4.9.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgfortran4-32bit-debuginfo", rpm:"libgfortran4-32bit-debuginfo~7.4.1+r275405~4.9.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgfortran4", rpm:"libgfortran4~7.4.1+r275405~4.9.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgfortran4-debuginfo", rpm:"libgfortran4-debuginfo~7.4.1+r275405~4.9.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libobjc4", rpm:"libobjc4~7.4.1+r275405~4.9.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libobjc4-debuginfo", rpm:"libobjc4-debuginfo~7.4.1+r275405~4.9.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-devel-gcc7", rpm:"libstdc++6-devel-gcc7~7.4.1+r275405~4.9.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libubsan0", rpm:"libubsan0~7.4.1+r275405~4.9.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libubsan0-debuginfo", rpm:"libubsan0-debuginfo~7.4.1+r275405~4.9.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-nvptx-gcc7", rpm:"cross-nvptx-gcc7~7.4.1+r275405~4.9.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-nvptx-newlib7-devel", rpm:"cross-nvptx-newlib7-devel~7.4.1+r275405~4.9.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-32bit", rpm:"gcc7-32bit~7.4.1+r275405~4.9.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-ada", rpm:"gcc7-ada~7.4.1+r275405~4.9.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-ada-debuginfo", rpm:"gcc7-ada-debuginfo~7.4.1+r275405~4.9.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-c++-32bit", rpm:"gcc7-c++-32bit~7.4.1+r275405~4.9.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-fortran-32bit", rpm:"gcc7-fortran-32bit~7.4.1+r275405~4.9.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-info", rpm:"gcc7-info~7.4.1+r275405~4.9.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-locale", rpm:"gcc7-locale~7.4.1+r275405~4.9.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-objc", rpm:"gcc7-objc~7.4.1+r275405~4.9.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-objc-debuginfo", rpm:"gcc7-objc-debuginfo~7.4.1+r275405~4.9.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libada7", rpm:"libada7~7.4.1+r275405~4.9.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libada7-debuginfo", rpm:"libada7-debuginfo~7.4.1+r275405~4.9.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasan4-32bit", rpm:"libasan4-32bit~7.4.1+r275405~4.9.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasan4-32bit-debuginfo", rpm:"libasan4-32bit-debuginfo~7.4.1+r275405~4.9.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcilkrts5-32bit", rpm:"libcilkrts5-32bit~7.4.1+r275405~4.9.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcilkrts5-32bit-debuginfo", rpm:"libcilkrts5-32bit-debuginfo~7.4.1+r275405~4.9.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-devel-gcc7-32bit", rpm:"libstdc++6-devel-gcc7-32bit~7.4.1+r275405~4.9.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libubsan0-32bit", rpm:"libubsan0-32bit~7.4.1+r275405~4.9.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libubsan0-32bit-debuginfo", rpm:"libubsan0-32bit-debuginfo~7.4.1+r275405~4.9.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"cpp7", rpm:"cpp7~7.4.1+r275405~4.9.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cpp7-debuginfo", rpm:"cpp7-debuginfo~7.4.1+r275405~4.9.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7", rpm:"gcc7~7.4.1+r275405~4.9.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-c++", rpm:"gcc7-c++~7.4.1+r275405~4.9.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-c++-debuginfo", rpm:"gcc7-c++-debuginfo~7.4.1+r275405~4.9.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-debuginfo", rpm:"gcc7-debuginfo~7.4.1+r275405~4.9.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-debugsource", rpm:"gcc7-debugsource~7.4.1+r275405~4.9.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-fortran", rpm:"gcc7-fortran~7.4.1+r275405~4.9.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-fortran-debuginfo", rpm:"gcc7-fortran-debuginfo~7.4.1+r275405~4.9.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasan4", rpm:"libasan4~7.4.1+r275405~4.9.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasan4-debuginfo", rpm:"libasan4-debuginfo~7.4.1+r275405~4.9.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcilkrts5", rpm:"libcilkrts5~7.4.1+r275405~4.9.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcilkrts5-debuginfo", rpm:"libcilkrts5-debuginfo~7.4.1+r275405~4.9.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgfortran4-32bit", rpm:"libgfortran4-32bit~7.4.1+r275405~4.9.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgfortran4-32bit-debuginfo", rpm:"libgfortran4-32bit-debuginfo~7.4.1+r275405~4.9.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgfortran4", rpm:"libgfortran4~7.4.1+r275405~4.9.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgfortran4-debuginfo", rpm:"libgfortran4-debuginfo~7.4.1+r275405~4.9.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libobjc4", rpm:"libobjc4~7.4.1+r275405~4.9.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libobjc4-debuginfo", rpm:"libobjc4-debuginfo~7.4.1+r275405~4.9.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-devel-gcc7", rpm:"libstdc++6-devel-gcc7~7.4.1+r275405~4.9.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libubsan0", rpm:"libubsan0~7.4.1+r275405~4.9.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libubsan0-debuginfo", rpm:"libubsan0-debuginfo~7.4.1+r275405~4.9.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-nvptx-gcc7", rpm:"cross-nvptx-gcc7~7.4.1+r275405~4.9.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-nvptx-newlib7-devel", rpm:"cross-nvptx-newlib7-devel~7.4.1+r275405~4.9.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-32bit", rpm:"gcc7-32bit~7.4.1+r275405~4.9.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-ada", rpm:"gcc7-ada~7.4.1+r275405~4.9.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-ada-debuginfo", rpm:"gcc7-ada-debuginfo~7.4.1+r275405~4.9.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-c++-32bit", rpm:"gcc7-c++-32bit~7.4.1+r275405~4.9.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-fortran-32bit", rpm:"gcc7-fortran-32bit~7.4.1+r275405~4.9.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-info", rpm:"gcc7-info~7.4.1+r275405~4.9.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-locale", rpm:"gcc7-locale~7.4.1+r275405~4.9.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-objc", rpm:"gcc7-objc~7.4.1+r275405~4.9.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-objc-debuginfo", rpm:"gcc7-objc-debuginfo~7.4.1+r275405~4.9.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libada7", rpm:"libada7~7.4.1+r275405~4.9.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libada7-debuginfo", rpm:"libada7-debuginfo~7.4.1+r275405~4.9.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasan4-32bit", rpm:"libasan4-32bit~7.4.1+r275405~4.9.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasan4-32bit-debuginfo", rpm:"libasan4-32bit-debuginfo~7.4.1+r275405~4.9.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcilkrts5-32bit", rpm:"libcilkrts5-32bit~7.4.1+r275405~4.9.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcilkrts5-32bit-debuginfo", rpm:"libcilkrts5-32bit-debuginfo~7.4.1+r275405~4.9.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-devel-gcc7-32bit", rpm:"libstdc++6-devel-gcc7-32bit~7.4.1+r275405~4.9.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libubsan0-32bit", rpm:"libubsan0-32bit~7.4.1+r275405~4.9.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libubsan0-32bit-debuginfo", rpm:"libubsan0-32bit-debuginfo~7.4.1+r275405~4.9.2", rls:"SLES15.0SP1"))) {
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
