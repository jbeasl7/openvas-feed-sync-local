# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833378");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2020-35357");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-11 16:12:35 +0000 (Wed, 11 Oct 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 08:02:59 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for gsl (SUSE-SU-2023:3858-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:3858-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/C3JGRDRNJUVGVZITHHCVFAA5HL5NH3KC");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gsl'
  package(s) announced via the SUSE-SU-2023:3858-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for gsl fixes the following issues:

  * CVE-2020-35357: Fixed a stack out of bounds read in
      gsl_stats_quantile_from_sorted_data(). (bsc#1214681)

  ##");

  script_tag(name:"affected", value:"'gsl' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5.");

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

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"gsl_2_6-gnu-hpc-doc", rpm:"gsl_2_6-gnu-hpc-doc~2.6~150200.3.4.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gsl_2_6-gnu-hpc-debugsource", rpm:"gsl_2_6-gnu-hpc-debugsource~2.6~150200.3.4.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gsl-debuginfo", rpm:"gsl-debuginfo~2.6~150200.3.4.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gsl-debugsource", rpm:"gsl-debugsource~2.6~150200.3.4.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsl-gnu-hpc", rpm:"libgsl-gnu-hpc~2.6~150200.3.4.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gsl-devel", rpm:"gsl-devel~2.6~150200.3.4.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gsl_2_6-gnu-hpc-devel", rpm:"gsl_2_6-gnu-hpc-devel~2.6~150200.3.4.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgslcblas0", rpm:"libgslcblas0~2.6~150200.3.4.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgslcblas_2_6-gnu-hpc-debuginfo", rpm:"libgslcblas_2_6-gnu-hpc-debuginfo~2.6~150200.3.4.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsl_2_6-gnu-hpc-debuginfo", rpm:"libgsl_2_6-gnu-hpc-debuginfo~2.6~150200.3.4.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsl25", rpm:"libgsl25~2.6~150200.3.4.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgslcblas-gnu-hpc", rpm:"libgslcblas-gnu-hpc~2.6~150200.3.4.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsl25-debuginfo", rpm:"libgsl25-debuginfo~2.6~150200.3.4.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gsl", rpm:"gsl~2.6~150200.3.4.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgslcblas_2_6-gnu-hpc", rpm:"libgslcblas_2_6-gnu-hpc~2.6~150200.3.4.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgslcblas0-debuginfo", rpm:"libgslcblas0-debuginfo~2.6~150200.3.4.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gsl_2_6-gnu-hpc-debuginfo", rpm:"gsl_2_6-gnu-hpc-debuginfo~2.6~150200.3.4.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsl_2_6-gnu-hpc", rpm:"libgsl_2_6-gnu-hpc~2.6~150200.3.4.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gsl-doc", rpm:"gsl-doc~2.6~150200.3.4.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gsl_2_6-gnu-hpc", rpm:"gsl_2_6-gnu-hpc~2.6~150200.3.4.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gsl_2_6-gnu-hpc-module", rpm:"gsl_2_6-gnu-hpc-module~2.6~150200.3.4.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gsl_2_6-gnu-hpc-examples", rpm:"gsl_2_6-gnu-hpc-examples~2.6~150200.3.4.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gsl-gnu-hpc-doc", rpm:"gsl-gnu-hpc-doc~2.6~150200.3.4.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gsl-examples", rpm:"gsl-examples~2.6~150200.3.4.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gsl-gnu-hpc", rpm:"gsl-gnu-hpc~2.6~150200.3.4.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gsl-gnu-hpc-devel", rpm:"gsl-gnu-hpc-devel~2.6~150200.3.4.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gsl_2_6-gnu-hpc-doc", rpm:"gsl_2_6-gnu-hpc-doc~2.6~150200.3.4.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gsl_2_6-gnu-hpc-debugsource", rpm:"gsl_2_6-gnu-hpc-debugsource~2.6~150200.3.4.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gsl-debuginfo", rpm:"gsl-debuginfo~2.6~150200.3.4.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gsl-debugsource", rpm:"gsl-debugsource~2.6~150200.3.4.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsl-gnu-hpc", rpm:"libgsl-gnu-hpc~2.6~150200.3.4.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gsl-devel", rpm:"gsl-devel~2.6~150200.3.4.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gsl_2_6-gnu-hpc-devel", rpm:"gsl_2_6-gnu-hpc-devel~2.6~150200.3.4.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgslcblas0", rpm:"libgslcblas0~2.6~150200.3.4.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgslcblas_2_6-gnu-hpc-debuginfo", rpm:"libgslcblas_2_6-gnu-hpc-debuginfo~2.6~150200.3.4.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsl_2_6-gnu-hpc-debuginfo", rpm:"libgsl_2_6-gnu-hpc-debuginfo~2.6~150200.3.4.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsl25", rpm:"libgsl25~2.6~150200.3.4.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgslcblas-gnu-hpc", rpm:"libgslcblas-gnu-hpc~2.6~150200.3.4.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsl25-debuginfo", rpm:"libgsl25-debuginfo~2.6~150200.3.4.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gsl", rpm:"gsl~2.6~150200.3.4.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgslcblas_2_6-gnu-hpc", rpm:"libgslcblas_2_6-gnu-hpc~2.6~150200.3.4.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgslcblas0-debuginfo", rpm:"libgslcblas0-debuginfo~2.6~150200.3.4.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gsl_2_6-gnu-hpc-debuginfo", rpm:"gsl_2_6-gnu-hpc-debuginfo~2.6~150200.3.4.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsl_2_6-gnu-hpc", rpm:"libgsl_2_6-gnu-hpc~2.6~150200.3.4.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gsl-doc", rpm:"gsl-doc~2.6~150200.3.4.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gsl_2_6-gnu-hpc", rpm:"gsl_2_6-gnu-hpc~2.6~150200.3.4.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gsl_2_6-gnu-hpc-module", rpm:"gsl_2_6-gnu-hpc-module~2.6~150200.3.4.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gsl_2_6-gnu-hpc-examples", rpm:"gsl_2_6-gnu-hpc-examples~2.6~150200.3.4.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gsl-gnu-hpc-doc", rpm:"gsl-gnu-hpc-doc~2.6~150200.3.4.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gsl-examples", rpm:"gsl-examples~2.6~150200.3.4.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gsl-gnu-hpc", rpm:"gsl-gnu-hpc~2.6~150200.3.4.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gsl-gnu-hpc-devel", rpm:"gsl-gnu-hpc-devel~2.6~150200.3.4.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"gsl_2_6-gnu-hpc-doc", rpm:"gsl_2_6-gnu-hpc-doc~2.6~150200.3.4.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gsl_2_6-gnu-hpc-debugsource", rpm:"gsl_2_6-gnu-hpc-debugsource~2.6~150200.3.4.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gsl-debuginfo", rpm:"gsl-debuginfo~2.6~150200.3.4.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gsl-debugsource", rpm:"gsl-debugsource~2.6~150200.3.4.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsl-gnu-hpc", rpm:"libgsl-gnu-hpc~2.6~150200.3.4.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gsl-devel", rpm:"gsl-devel~2.6~150200.3.4.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gsl_2_6-gnu-hpc-devel", rpm:"gsl_2_6-gnu-hpc-devel~2.6~150200.3.4.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgslcblas0", rpm:"libgslcblas0~2.6~150200.3.4.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgslcblas_2_6-gnu-hpc-debuginfo", rpm:"libgslcblas_2_6-gnu-hpc-debuginfo~2.6~150200.3.4.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsl_2_6-gnu-hpc-debuginfo", rpm:"libgsl_2_6-gnu-hpc-debuginfo~2.6~150200.3.4.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsl25", rpm:"libgsl25~2.6~150200.3.4.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgslcblas-gnu-hpc", rpm:"libgslcblas-gnu-hpc~2.6~150200.3.4.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsl25-debuginfo", rpm:"libgsl25-debuginfo~2.6~150200.3.4.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gsl", rpm:"gsl~2.6~150200.3.4.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgslcblas_2_6-gnu-hpc", rpm:"libgslcblas_2_6-gnu-hpc~2.6~150200.3.4.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgslcblas0-debuginfo", rpm:"libgslcblas0-debuginfo~2.6~150200.3.4.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gsl_2_6-gnu-hpc-debuginfo", rpm:"gsl_2_6-gnu-hpc-debuginfo~2.6~150200.3.4.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsl_2_6-gnu-hpc", rpm:"libgsl_2_6-gnu-hpc~2.6~150200.3.4.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gsl-doc", rpm:"gsl-doc~2.6~150200.3.4.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gsl_2_6-gnu-hpc", rpm:"gsl_2_6-gnu-hpc~2.6~150200.3.4.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gsl_2_6-gnu-hpc-module", rpm:"gsl_2_6-gnu-hpc-module~2.6~150200.3.4.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gsl_2_6-gnu-hpc-examples", rpm:"gsl_2_6-gnu-hpc-examples~2.6~150200.3.4.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gsl-gnu-hpc-doc", rpm:"gsl-gnu-hpc-doc~2.6~150200.3.4.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gsl-examples", rpm:"gsl-examples~2.6~150200.3.4.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gsl-gnu-hpc", rpm:"gsl-gnu-hpc~2.6~150200.3.4.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gsl-gnu-hpc-devel", rpm:"gsl-gnu-hpc-devel~2.6~150200.3.4.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gsl_2_6-gnu-hpc-doc", rpm:"gsl_2_6-gnu-hpc-doc~2.6~150200.3.4.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gsl_2_6-gnu-hpc-debugsource", rpm:"gsl_2_6-gnu-hpc-debugsource~2.6~150200.3.4.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gsl-debuginfo", rpm:"gsl-debuginfo~2.6~150200.3.4.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gsl-debugsource", rpm:"gsl-debugsource~2.6~150200.3.4.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsl-gnu-hpc", rpm:"libgsl-gnu-hpc~2.6~150200.3.4.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gsl-devel", rpm:"gsl-devel~2.6~150200.3.4.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gsl_2_6-gnu-hpc-devel", rpm:"gsl_2_6-gnu-hpc-devel~2.6~150200.3.4.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgslcblas0", rpm:"libgslcblas0~2.6~150200.3.4.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgslcblas_2_6-gnu-hpc-debuginfo", rpm:"libgslcblas_2_6-gnu-hpc-debuginfo~2.6~150200.3.4.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsl_2_6-gnu-hpc-debuginfo", rpm:"libgsl_2_6-gnu-hpc-debuginfo~2.6~150200.3.4.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsl25", rpm:"libgsl25~2.6~150200.3.4.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgslcblas-gnu-hpc", rpm:"libgslcblas-gnu-hpc~2.6~150200.3.4.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsl25-debuginfo", rpm:"libgsl25-debuginfo~2.6~150200.3.4.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gsl", rpm:"gsl~2.6~150200.3.4.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgslcblas_2_6-gnu-hpc", rpm:"libgslcblas_2_6-gnu-hpc~2.6~150200.3.4.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgslcblas0-debuginfo", rpm:"libgslcblas0-debuginfo~2.6~150200.3.4.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gsl_2_6-gnu-hpc-debuginfo", rpm:"gsl_2_6-gnu-hpc-debuginfo~2.6~150200.3.4.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsl_2_6-gnu-hpc", rpm:"libgsl_2_6-gnu-hpc~2.6~150200.3.4.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gsl-doc", rpm:"gsl-doc~2.6~150200.3.4.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gsl_2_6-gnu-hpc", rpm:"gsl_2_6-gnu-hpc~2.6~150200.3.4.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gsl_2_6-gnu-hpc-module", rpm:"gsl_2_6-gnu-hpc-module~2.6~150200.3.4.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gsl_2_6-gnu-hpc-examples", rpm:"gsl_2_6-gnu-hpc-examples~2.6~150200.3.4.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gsl-gnu-hpc-doc", rpm:"gsl-gnu-hpc-doc~2.6~150200.3.4.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gsl-examples", rpm:"gsl-examples~2.6~150200.3.4.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gsl-gnu-hpc", rpm:"gsl-gnu-hpc~2.6~150200.3.4.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gsl-gnu-hpc-devel", rpm:"gsl-gnu-hpc-devel~2.6~150200.3.4.3", rls:"openSUSELeap15.5"))) {
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