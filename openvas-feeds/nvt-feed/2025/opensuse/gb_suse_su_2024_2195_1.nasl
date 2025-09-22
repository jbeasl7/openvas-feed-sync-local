# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2024.2195.1");
  script_cve_id("CVE-2017-17507", "CVE-2018-11205", "CVE-2024-29158", "CVE-2024-29161", "CVE-2024-29166", "CVE-2024-32608", "CVE-2024-32610", "CVE-2024-32614", "CVE-2024-32619", "CVE-2024-32620", "CVE-2024-33873", "CVE-2024-33874", "CVE-2024-33875");
  script_tag(name:"creation_date", value:"2025-02-25 14:26:30 +0000 (Tue, 25 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-17 16:47:02 +0000 (Thu, 17 Oct 2024)");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:2195-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5|openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2195-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20242195-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224158");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2024-June/035729.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'hdf5' package(s) announced via the SUSE-SU-2024:2195-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for hdf5 fixes the following issues:

- Fix bsc#1224158 - this fixes:
 CVE-2024-29158, CVE-2024-29161, CVE-2024-29166, CVE-2024-32608,
 CVE-2024-32610, CVE-2024-32614, CVE-2024-32619, CVE-2024-32620,
 CVE-2024-33873, CVE-2024-33874, CVE-2024-33875
 Additionally, these fixes resolve crashes triggered by the
 reproducers for CVE-2017-17507, CVE-2018-11205. These crashes
 appear to be unrelated to the original problems.


This update also ships several missing PackageHub packages for 15 SP5 and 15 SP6.");

  script_tag(name:"affected", value:"'hdf5' package(s) on openSUSE Leap 15.5, openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"hdf5-gnu-hpc", rpm:"hdf5-gnu-hpc~1.10.11~150400.3.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5-gnu-hpc-devel", rpm:"hdf5-gnu-hpc-devel~1.10.11~150400.3.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5-gnu-mpich-hpc", rpm:"hdf5-gnu-mpich-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5-gnu-mpich-hpc-devel", rpm:"hdf5-gnu-mpich-hpc-devel~1.10.11~150400.3.17.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5-gnu-mvapich2-hpc", rpm:"hdf5-gnu-mvapich2-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5-gnu-mvapich2-hpc-devel", rpm:"hdf5-gnu-mvapich2-hpc-devel~1.10.11~150400.3.17.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5-gnu-openmpi3-hpc", rpm:"hdf5-gnu-openmpi3-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5-gnu-openmpi3-hpc-devel", rpm:"hdf5-gnu-openmpi3-hpc-devel~1.10.11~150400.3.17.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5-gnu-openmpi4-hpc", rpm:"hdf5-gnu-openmpi4-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5-gnu-openmpi4-hpc-devel", rpm:"hdf5-gnu-openmpi4-hpc-devel~1.10.11~150400.3.17.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5-hpc-examples", rpm:"hdf5-hpc-examples~1.10.11~150400.3.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-hpc", rpm:"hdf5_1_10_11-gnu-hpc~1.10.11~150400.3.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-hpc-devel", rpm:"hdf5_1_10_11-gnu-hpc-devel~1.10.11~150400.3.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-hpc-devel-static", rpm:"hdf5_1_10_11-gnu-hpc-devel-static~1.10.11~150400.3.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-hpc-module", rpm:"hdf5_1_10_11-gnu-hpc-module~1.10.11~150400.3.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-mpich-hpc", rpm:"hdf5_1_10_11-gnu-mpich-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-mpich-hpc-devel", rpm:"hdf5_1_10_11-gnu-mpich-hpc-devel~1.10.11~150400.3.17.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-mpich-hpc-devel-static", rpm:"hdf5_1_10_11-gnu-mpich-hpc-devel-static~1.10.11~150400.3.17.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-mpich-hpc-module", rpm:"hdf5_1_10_11-gnu-mpich-hpc-module~1.10.11~150400.3.17.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-mvapich2-hpc", rpm:"hdf5_1_10_11-gnu-mvapich2-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-mvapich2-hpc-devel", rpm:"hdf5_1_10_11-gnu-mvapich2-hpc-devel~1.10.11~150400.3.17.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-mvapich2-hpc-devel-static", rpm:"hdf5_1_10_11-gnu-mvapich2-hpc-devel-static~1.10.11~150400.3.17.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-mvapich2-hpc-module", rpm:"hdf5_1_10_11-gnu-mvapich2-hpc-module~1.10.11~150400.3.17.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-openmpi3-hpc", rpm:"hdf5_1_10_11-gnu-openmpi3-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-openmpi3-hpc-devel", rpm:"hdf5_1_10_11-gnu-openmpi3-hpc-devel~1.10.11~150400.3.17.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-openmpi3-hpc-devel-static", rpm:"hdf5_1_10_11-gnu-openmpi3-hpc-devel-static~1.10.11~150400.3.17.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-openmpi3-hpc-module", rpm:"hdf5_1_10_11-gnu-openmpi3-hpc-module~1.10.11~150400.3.17.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-openmpi4-hpc", rpm:"hdf5_1_10_11-gnu-openmpi4-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-openmpi4-hpc-devel", rpm:"hdf5_1_10_11-gnu-openmpi4-hpc-devel~1.10.11~150400.3.17.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-openmpi4-hpc-devel-static", rpm:"hdf5_1_10_11-gnu-openmpi4-hpc-devel-static~1.10.11~150400.3.17.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-openmpi4-hpc-module", rpm:"hdf5_1_10_11-gnu-openmpi4-hpc-module~1.10.11~150400.3.17.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-hpc-examples", rpm:"hdf5_1_10_11-hpc-examples~1.10.11~150400.3.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5-gnu-hpc", rpm:"libhdf5-gnu-hpc~1.10.11~150400.3.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5-gnu-mpich-hpc", rpm:"libhdf5-gnu-mpich-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5-gnu-mvapich2-hpc", rpm:"libhdf5-gnu-mvapich2-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5-gnu-openmpi3-hpc", rpm:"libhdf5-gnu-openmpi3-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5-gnu-openmpi4-hpc", rpm:"libhdf5-gnu-openmpi4-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_1_10_11-gnu-hpc", rpm:"libhdf5_1_10_11-gnu-hpc~1.10.11~150400.3.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_1_10_11-gnu-mpich-hpc", rpm:"libhdf5_1_10_11-gnu-mpich-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_1_10_11-gnu-mvapich2-hpc", rpm:"libhdf5_1_10_11-gnu-mvapich2-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_1_10_11-gnu-openmpi3-hpc", rpm:"libhdf5_1_10_11-gnu-openmpi3-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_1_10_11-gnu-openmpi4-hpc", rpm:"libhdf5_1_10_11-gnu-openmpi4-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_cpp-gnu-hpc", rpm:"libhdf5_cpp-gnu-hpc~1.10.11~150400.3.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_cpp-gnu-mpich-hpc", rpm:"libhdf5_cpp-gnu-mpich-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_cpp-gnu-mvapich2-hpc", rpm:"libhdf5_cpp-gnu-mvapich2-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_cpp-gnu-openmpi3-hpc", rpm:"libhdf5_cpp-gnu-openmpi3-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_cpp-gnu-openmpi4-hpc", rpm:"libhdf5_cpp-gnu-openmpi4-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_cpp_1_10_11-gnu-hpc", rpm:"libhdf5_cpp_1_10_11-gnu-hpc~1.10.11~150400.3.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_cpp_1_10_11-gnu-mpich-hpc", rpm:"libhdf5_cpp_1_10_11-gnu-mpich-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_cpp_1_10_11-gnu-mvapich2-hpc", rpm:"libhdf5_cpp_1_10_11-gnu-mvapich2-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_cpp_1_10_11-gnu-openmpi3-hpc", rpm:"libhdf5_cpp_1_10_11-gnu-openmpi3-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_cpp_1_10_11-gnu-openmpi4-hpc", rpm:"libhdf5_cpp_1_10_11-gnu-openmpi4-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_fortran-gnu-hpc", rpm:"libhdf5_fortran-gnu-hpc~1.10.11~150400.3.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_fortran-gnu-mpich-hpc", rpm:"libhdf5_fortran-gnu-mpich-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_fortran-gnu-mvapich2-hpc", rpm:"libhdf5_fortran-gnu-mvapich2-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_fortran-gnu-openmpi3-hpc", rpm:"libhdf5_fortran-gnu-openmpi3-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_fortran-gnu-openmpi4-hpc", rpm:"libhdf5_fortran-gnu-openmpi4-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_fortran_1_10_11-gnu-hpc", rpm:"libhdf5_fortran_1_10_11-gnu-hpc~1.10.11~150400.3.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_fortran_1_10_11-gnu-mpich-hpc", rpm:"libhdf5_fortran_1_10_11-gnu-mpich-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_fortran_1_10_11-gnu-mvapich2-hpc", rpm:"libhdf5_fortran_1_10_11-gnu-mvapich2-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_fortran_1_10_11-gnu-openmpi3-hpc", rpm:"libhdf5_fortran_1_10_11-gnu-openmpi3-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_fortran_1_10_11-gnu-openmpi4-hpc", rpm:"libhdf5_fortran_1_10_11-gnu-openmpi4-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl-gnu-hpc", rpm:"libhdf5_hl-gnu-hpc~1.10.11~150400.3.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl-gnu-mpich-hpc", rpm:"libhdf5_hl-gnu-mpich-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl-gnu-mvapich2-hpc", rpm:"libhdf5_hl-gnu-mvapich2-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl-gnu-openmpi3-hpc", rpm:"libhdf5_hl-gnu-openmpi3-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl-gnu-openmpi4-hpc", rpm:"libhdf5_hl-gnu-openmpi4-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_1_10_11-gnu-hpc", rpm:"libhdf5_hl_1_10_11-gnu-hpc~1.10.11~150400.3.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_1_10_11-gnu-mpich-hpc", rpm:"libhdf5_hl_1_10_11-gnu-mpich-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_1_10_11-gnu-mvapich2-hpc", rpm:"libhdf5_hl_1_10_11-gnu-mvapich2-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_1_10_11-gnu-openmpi3-hpc", rpm:"libhdf5_hl_1_10_11-gnu-openmpi3-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_1_10_11-gnu-openmpi4-hpc", rpm:"libhdf5_hl_1_10_11-gnu-openmpi4-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_cpp-gnu-hpc", rpm:"libhdf5_hl_cpp-gnu-hpc~1.10.11~150400.3.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_cpp-gnu-mpich-hpc", rpm:"libhdf5_hl_cpp-gnu-mpich-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_cpp-gnu-mvapich2-hpc", rpm:"libhdf5_hl_cpp-gnu-mvapich2-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_cpp-gnu-openmpi3-hpc", rpm:"libhdf5_hl_cpp-gnu-openmpi3-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_cpp-gnu-openmpi4-hpc", rpm:"libhdf5_hl_cpp-gnu-openmpi4-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_cpp_1_10_11-gnu-hpc", rpm:"libhdf5_hl_cpp_1_10_11-gnu-hpc~1.10.11~150400.3.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_cpp_1_10_11-gnu-mpich-hpc", rpm:"libhdf5_hl_cpp_1_10_11-gnu-mpich-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_cpp_1_10_11-gnu-mvapich2-hpc", rpm:"libhdf5_hl_cpp_1_10_11-gnu-mvapich2-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_cpp_1_10_11-gnu-openmpi3-hpc", rpm:"libhdf5_hl_cpp_1_10_11-gnu-openmpi3-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_cpp_1_10_11-gnu-openmpi4-hpc", rpm:"libhdf5_hl_cpp_1_10_11-gnu-openmpi4-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_fortran-gnu-hpc", rpm:"libhdf5_hl_fortran-gnu-hpc~1.10.11~150400.3.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_fortran-gnu-mpich-hpc", rpm:"libhdf5_hl_fortran-gnu-mpich-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_fortran-gnu-mvapich2-hpc", rpm:"libhdf5_hl_fortran-gnu-mvapich2-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_fortran-gnu-openmpi3-hpc", rpm:"libhdf5_hl_fortran-gnu-openmpi3-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_fortran-gnu-openmpi4-hpc", rpm:"libhdf5_hl_fortran-gnu-openmpi4-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5hl_fortran_1_10_11-gnu-hpc", rpm:"libhdf5hl_fortran_1_10_11-gnu-hpc~1.10.11~150400.3.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5hl_fortran_1_10_11-gnu-mpich-hpc", rpm:"libhdf5hl_fortran_1_10_11-gnu-mpich-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5hl_fortran_1_10_11-gnu-mvapich2-hpc", rpm:"libhdf5hl_fortran_1_10_11-gnu-mvapich2-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5hl_fortran_1_10_11-gnu-openmpi3-hpc", rpm:"libhdf5hl_fortran_1_10_11-gnu-openmpi3-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5hl_fortran_1_10_11-gnu-openmpi4-hpc", rpm:"libhdf5hl_fortran_1_10_11-gnu-openmpi4-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmca_common_dstore1", rpm:"libmca_common_dstore1~3.2.3~150300.3.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenmpi4-gnu-hpc", rpm:"libopenmpi4-gnu-hpc~4.1.4~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenmpi_4_1_4-gnu-hpc", rpm:"libopenmpi_4_1_4-gnu-hpc~4.1.4~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpmix2", rpm:"libpmix2~3.2.3~150300.3.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lua51-luaposix", rpm:"lua51-luaposix~34.1.1~150200.3.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lua51-luaterm", rpm:"lua51-luaterm~0.07~150000.5.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lua53-luaposix", rpm:"lua53-luaposix~34.1.1~150200.3.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lua53-luaterm", rpm:"lua53-luaterm~0.07~150000.5.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"luaposix-doc", rpm:"luaposix-doc~34.1.1~150200.3.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mpich", rpm:"mpich~4.0.2~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mpich-devel", rpm:"mpich-devel~4.0.2~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mpich-gnu-hpc", rpm:"mpich-gnu-hpc~4.0.2~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mpich-gnu-hpc-devel", rpm:"mpich-gnu-hpc-devel~4.0.2~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mpich-gnu-hpc-devel-static", rpm:"mpich-gnu-hpc-devel-static~4.0.2~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mpich-gnu-hpc-macros-devel", rpm:"mpich-gnu-hpc-macros-devel~4.0.2~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mpich-ofi", rpm:"mpich-ofi~4.0.2~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mpich-ofi-devel", rpm:"mpich-ofi-devel~4.0.2~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mpich-ofi-gnu-hpc", rpm:"mpich-ofi-gnu-hpc~4.0.2~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mpich-ofi-gnu-hpc-devel", rpm:"mpich-ofi-gnu-hpc-devel~4.0.2~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mpich-ofi-gnu-hpc-devel-static", rpm:"mpich-ofi-gnu-hpc-devel-static~4.0.2~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mpich-ofi-gnu-hpc-macros-devel", rpm:"mpich-ofi-gnu-hpc-macros-devel~4.0.2~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mpich-ofi_4_0_2-gnu-hpc", rpm:"mpich-ofi_4_0_2-gnu-hpc~4.0.2~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mpich-ofi_4_0_2-gnu-hpc-devel", rpm:"mpich-ofi_4_0_2-gnu-hpc-devel~4.0.2~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mpich-ofi_4_0_2-gnu-hpc-devel-static", rpm:"mpich-ofi_4_0_2-gnu-hpc-devel-static~4.0.2~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mpich-ofi_4_0_2-gnu-hpc-macros-devel", rpm:"mpich-ofi_4_0_2-gnu-hpc-macros-devel~4.0.2~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mpich_4_0_2-gnu-hpc", rpm:"mpich_4_0_2-gnu-hpc~4.0.2~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mpich_4_0_2-gnu-hpc-devel", rpm:"mpich_4_0_2-gnu-hpc-devel~4.0.2~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mpich_4_0_2-gnu-hpc-devel-static", rpm:"mpich_4_0_2-gnu-hpc-devel-static~4.0.2~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mpich_4_0_2-gnu-hpc-macros-devel", rpm:"mpich_4_0_2-gnu-hpc-macros-devel~4.0.2~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvapich2", rpm:"mvapich2~2.3.7~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvapich2-devel", rpm:"mvapich2-devel~2.3.7~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvapich2-devel-static", rpm:"mvapich2-devel-static~2.3.7~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvapich2-doc", rpm:"mvapich2-doc~2.3.7~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvapich2-gnu-hpc", rpm:"mvapich2-gnu-hpc~2.3.7~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvapich2-gnu-hpc-devel", rpm:"mvapich2-gnu-hpc-devel~2.3.7~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvapich2-gnu-hpc-doc", rpm:"mvapich2-gnu-hpc-doc~2.3.7~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvapich2-gnu-hpc-macros-devel", rpm:"mvapich2-gnu-hpc-macros-devel~2.3.7~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvapich2-psm", rpm:"mvapich2-psm~2.3.7~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvapich2-psm-devel", rpm:"mvapich2-psm-devel~2.3.7~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvapich2-psm-devel-static", rpm:"mvapich2-psm-devel-static~2.3.7~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvapich2-psm-doc", rpm:"mvapich2-psm-doc~2.3.7~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvapich2-psm-gnu-hpc", rpm:"mvapich2-psm-gnu-hpc~2.3.7~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvapich2-psm-gnu-hpc-devel", rpm:"mvapich2-psm-gnu-hpc-devel~2.3.7~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvapich2-psm-gnu-hpc-doc", rpm:"mvapich2-psm-gnu-hpc-doc~2.3.7~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvapich2-psm-gnu-hpc-macros-devel", rpm:"mvapich2-psm-gnu-hpc-macros-devel~2.3.7~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvapich2-psm2", rpm:"mvapich2-psm2~2.3.7~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvapich2-psm2-devel", rpm:"mvapich2-psm2-devel~2.3.7~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvapich2-psm2-devel-static", rpm:"mvapich2-psm2-devel-static~2.3.7~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvapich2-psm2-doc", rpm:"mvapich2-psm2-doc~2.3.7~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvapich2-psm2-gnu-hpc", rpm:"mvapich2-psm2-gnu-hpc~2.3.7~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvapich2-psm2-gnu-hpc-devel", rpm:"mvapich2-psm2-gnu-hpc-devel~2.3.7~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvapich2-psm2-gnu-hpc-doc", rpm:"mvapich2-psm2-gnu-hpc-doc~2.3.7~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvapich2-psm2-gnu-hpc-macros-devel", rpm:"mvapich2-psm2-gnu-hpc-macros-devel~2.3.7~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvapich2-psm2_2_3_7-gnu-hpc", rpm:"mvapich2-psm2_2_3_7-gnu-hpc~2.3.7~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvapich2-psm2_2_3_7-gnu-hpc-devel", rpm:"mvapich2-psm2_2_3_7-gnu-hpc-devel~2.3.7~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvapich2-psm2_2_3_7-gnu-hpc-devel-static", rpm:"mvapich2-psm2_2_3_7-gnu-hpc-devel-static~2.3.7~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvapich2-psm2_2_3_7-gnu-hpc-doc", rpm:"mvapich2-psm2_2_3_7-gnu-hpc-doc~2.3.7~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvapich2-psm2_2_3_7-gnu-hpc-macros-devel", rpm:"mvapich2-psm2_2_3_7-gnu-hpc-macros-devel~2.3.7~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvapich2-psm_2_3_7-gnu-hpc", rpm:"mvapich2-psm_2_3_7-gnu-hpc~2.3.7~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvapich2-psm_2_3_7-gnu-hpc-devel", rpm:"mvapich2-psm_2_3_7-gnu-hpc-devel~2.3.7~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvapich2-psm_2_3_7-gnu-hpc-devel-static", rpm:"mvapich2-psm_2_3_7-gnu-hpc-devel-static~2.3.7~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvapich2-psm_2_3_7-gnu-hpc-doc", rpm:"mvapich2-psm_2_3_7-gnu-hpc-doc~2.3.7~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvapich2-psm_2_3_7-gnu-hpc-macros-devel", rpm:"mvapich2-psm_2_3_7-gnu-hpc-macros-devel~2.3.7~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvapich2_2_3_7-gnu-hpc", rpm:"mvapich2_2_3_7-gnu-hpc~2.3.7~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvapich2_2_3_7-gnu-hpc-devel", rpm:"mvapich2_2_3_7-gnu-hpc-devel~2.3.7~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvapich2_2_3_7-gnu-hpc-devel-static", rpm:"mvapich2_2_3_7-gnu-hpc-devel-static~2.3.7~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvapich2_2_3_7-gnu-hpc-doc", rpm:"mvapich2_2_3_7-gnu-hpc-doc~2.3.7~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvapich2_2_3_7-gnu-hpc-macros-devel", rpm:"mvapich2_2_3_7-gnu-hpc-macros-devel~2.3.7~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openmpi4", rpm:"openmpi4~4.1.4~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openmpi4-config", rpm:"openmpi4-config~4.1.4~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openmpi4-devel", rpm:"openmpi4-devel~4.1.4~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openmpi4-docs", rpm:"openmpi4-docs~4.1.4~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openmpi4-gnu-hpc", rpm:"openmpi4-gnu-hpc~4.1.4~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openmpi4-gnu-hpc-devel", rpm:"openmpi4-gnu-hpc-devel~4.1.4~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openmpi4-gnu-hpc-devel-static", rpm:"openmpi4-gnu-hpc-devel-static~4.1.4~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openmpi4-gnu-hpc-docs", rpm:"openmpi4-gnu-hpc-docs~4.1.4~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openmpi4-gnu-hpc-macros-devel", rpm:"openmpi4-gnu-hpc-macros-devel~4.1.4~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openmpi4-libs-32bit", rpm:"openmpi4-libs-32bit~4.1.4~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openmpi4-libs", rpm:"openmpi4-libs~4.1.4~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openmpi4-macros-devel", rpm:"openmpi4-macros-devel~4.1.4~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openmpi4-testsuite", rpm:"openmpi4-testsuite~4.1.4~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openmpi_4_1_4-gnu-hpc", rpm:"openmpi_4_1_4-gnu-hpc~4.1.4~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openmpi_4_1_4-gnu-hpc-devel", rpm:"openmpi_4_1_4-gnu-hpc-devel~4.1.4~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openmpi_4_1_4-gnu-hpc-devel-static", rpm:"openmpi_4_1_4-gnu-hpc-devel-static~4.1.4~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openmpi_4_1_4-gnu-hpc-docs", rpm:"openmpi_4_1_4-gnu-hpc-docs~4.1.4~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openmpi_4_1_4-gnu-hpc-macros-devel", rpm:"openmpi_4_1_4-gnu-hpc-macros-devel~4.1.4~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openmpi_4_1_4-gnu-hpc-testsuite", rpm:"openmpi_4_1_4-gnu-hpc-testsuite~4.1.4~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pmix", rpm:"pmix~3.2.3~150300.3.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pmix-devel", rpm:"pmix-devel~3.2.3~150300.3.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pmix-headers", rpm:"pmix-headers~3.2.3~150300.3.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pmix-mca-params", rpm:"pmix-mca-params~3.2.3~150300.3.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pmix-plugin-munge", rpm:"pmix-plugin-munge~3.2.3~150300.3.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pmix-plugins", rpm:"pmix-plugins~3.2.3~150300.3.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pmix-test", rpm:"pmix-test~3.2.3~150300.3.10.1", rls:"openSUSELeap15.5"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-hpc", rpm:"hdf5_1_10_11-gnu-hpc~1.10.11~150400.3.17.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-hpc-devel", rpm:"hdf5_1_10_11-gnu-hpc-devel~1.10.11~150400.3.17.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-hpc-devel-static", rpm:"hdf5_1_10_11-gnu-hpc-devel-static~1.10.11~150400.3.17.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-hpc-module", rpm:"hdf5_1_10_11-gnu-hpc-module~1.10.11~150400.3.17.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-mpich-hpc", rpm:"hdf5_1_10_11-gnu-mpich-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-mpich-hpc-devel", rpm:"hdf5_1_10_11-gnu-mpich-hpc-devel~1.10.11~150400.3.17.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-mpich-hpc-devel-static", rpm:"hdf5_1_10_11-gnu-mpich-hpc-devel-static~1.10.11~150400.3.17.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-mpich-hpc-module", rpm:"hdf5_1_10_11-gnu-mpich-hpc-module~1.10.11~150400.3.17.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-mvapich2-hpc", rpm:"hdf5_1_10_11-gnu-mvapich2-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-mvapich2-hpc-devel", rpm:"hdf5_1_10_11-gnu-mvapich2-hpc-devel~1.10.11~150400.3.17.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-mvapich2-hpc-devel-static", rpm:"hdf5_1_10_11-gnu-mvapich2-hpc-devel-static~1.10.11~150400.3.17.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-mvapich2-hpc-module", rpm:"hdf5_1_10_11-gnu-mvapich2-hpc-module~1.10.11~150400.3.17.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-openmpi3-hpc", rpm:"hdf5_1_10_11-gnu-openmpi3-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-openmpi3-hpc-devel", rpm:"hdf5_1_10_11-gnu-openmpi3-hpc-devel~1.10.11~150400.3.17.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-openmpi3-hpc-devel-static", rpm:"hdf5_1_10_11-gnu-openmpi3-hpc-devel-static~1.10.11~150400.3.17.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-openmpi3-hpc-module", rpm:"hdf5_1_10_11-gnu-openmpi3-hpc-module~1.10.11~150400.3.17.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-openmpi4-hpc", rpm:"hdf5_1_10_11-gnu-openmpi4-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-openmpi4-hpc-devel", rpm:"hdf5_1_10_11-gnu-openmpi4-hpc-devel~1.10.11~150400.3.17.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-openmpi4-hpc-devel-static", rpm:"hdf5_1_10_11-gnu-openmpi4-hpc-devel-static~1.10.11~150400.3.17.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-openmpi4-hpc-module", rpm:"hdf5_1_10_11-gnu-openmpi4-hpc-module~1.10.11~150400.3.17.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-hpc-examples", rpm:"hdf5_1_10_11-hpc-examples~1.10.11~150400.3.17.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_1_10_11-gnu-hpc", rpm:"libhdf5_1_10_11-gnu-hpc~1.10.11~150400.3.17.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_1_10_11-gnu-mpich-hpc", rpm:"libhdf5_1_10_11-gnu-mpich-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_1_10_11-gnu-mvapich2-hpc", rpm:"libhdf5_1_10_11-gnu-mvapich2-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_1_10_11-gnu-openmpi3-hpc", rpm:"libhdf5_1_10_11-gnu-openmpi3-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_1_10_11-gnu-openmpi4-hpc", rpm:"libhdf5_1_10_11-gnu-openmpi4-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_cpp_1_10_11-gnu-hpc", rpm:"libhdf5_cpp_1_10_11-gnu-hpc~1.10.11~150400.3.17.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_cpp_1_10_11-gnu-mpich-hpc", rpm:"libhdf5_cpp_1_10_11-gnu-mpich-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_cpp_1_10_11-gnu-mvapich2-hpc", rpm:"libhdf5_cpp_1_10_11-gnu-mvapich2-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_cpp_1_10_11-gnu-openmpi3-hpc", rpm:"libhdf5_cpp_1_10_11-gnu-openmpi3-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_cpp_1_10_11-gnu-openmpi4-hpc", rpm:"libhdf5_cpp_1_10_11-gnu-openmpi4-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_fortran_1_10_11-gnu-hpc", rpm:"libhdf5_fortran_1_10_11-gnu-hpc~1.10.11~150400.3.17.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_fortran_1_10_11-gnu-mpich-hpc", rpm:"libhdf5_fortran_1_10_11-gnu-mpich-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_fortran_1_10_11-gnu-mvapich2-hpc", rpm:"libhdf5_fortran_1_10_11-gnu-mvapich2-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_fortran_1_10_11-gnu-openmpi3-hpc", rpm:"libhdf5_fortran_1_10_11-gnu-openmpi3-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_fortran_1_10_11-gnu-openmpi4-hpc", rpm:"libhdf5_fortran_1_10_11-gnu-openmpi4-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_1_10_11-gnu-hpc", rpm:"libhdf5_hl_1_10_11-gnu-hpc~1.10.11~150400.3.17.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_1_10_11-gnu-mpich-hpc", rpm:"libhdf5_hl_1_10_11-gnu-mpich-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_1_10_11-gnu-mvapich2-hpc", rpm:"libhdf5_hl_1_10_11-gnu-mvapich2-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_1_10_11-gnu-openmpi3-hpc", rpm:"libhdf5_hl_1_10_11-gnu-openmpi3-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_1_10_11-gnu-openmpi4-hpc", rpm:"libhdf5_hl_1_10_11-gnu-openmpi4-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_cpp_1_10_11-gnu-hpc", rpm:"libhdf5_hl_cpp_1_10_11-gnu-hpc~1.10.11~150400.3.17.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_cpp_1_10_11-gnu-mpich-hpc", rpm:"libhdf5_hl_cpp_1_10_11-gnu-mpich-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_cpp_1_10_11-gnu-mvapich2-hpc", rpm:"libhdf5_hl_cpp_1_10_11-gnu-mvapich2-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_cpp_1_10_11-gnu-openmpi3-hpc", rpm:"libhdf5_hl_cpp_1_10_11-gnu-openmpi3-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_cpp_1_10_11-gnu-openmpi4-hpc", rpm:"libhdf5_hl_cpp_1_10_11-gnu-openmpi4-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5hl_fortran_1_10_11-gnu-hpc", rpm:"libhdf5hl_fortran_1_10_11-gnu-hpc~1.10.11~150400.3.17.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5hl_fortran_1_10_11-gnu-mpich-hpc", rpm:"libhdf5hl_fortran_1_10_11-gnu-mpich-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5hl_fortran_1_10_11-gnu-mvapich2-hpc", rpm:"libhdf5hl_fortran_1_10_11-gnu-mvapich2-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5hl_fortran_1_10_11-gnu-openmpi3-hpc", rpm:"libhdf5hl_fortran_1_10_11-gnu-openmpi3-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5hl_fortran_1_10_11-gnu-openmpi4-hpc", rpm:"libhdf5hl_fortran_1_10_11-gnu-openmpi4-hpc~1.10.11~150400.3.17.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmca_common_dstore1", rpm:"libmca_common_dstore1~3.2.3~150300.3.10.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenmpi4-gnu-hpc", rpm:"libopenmpi4-gnu-hpc~4.1.6~150600.3.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenmpi_4_1_4-gnu-hpc", rpm:"libopenmpi_4_1_4-gnu-hpc~4.1.4~150500.3.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenmpi_4_1_6-gnu-hpc", rpm:"libopenmpi_4_1_6-gnu-hpc~4.1.6~150600.3.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpmix2", rpm:"libpmix2~3.2.3~150300.3.10.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lua51-luaposix", rpm:"lua51-luaposix~34.1.1~150200.3.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lua51-luaterm", rpm:"lua51-luaterm~0.07~150000.5.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lua53-luaposix", rpm:"lua53-luaposix~34.1.1~150200.3.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lua53-luaterm", rpm:"lua53-luaterm~0.07~150000.5.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"luaposix-doc", rpm:"luaposix-doc~34.1.1~150200.3.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mpich", rpm:"mpich~4.1.2~150600.3.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mpich-devel", rpm:"mpich-devel~4.1.2~150600.3.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mpich-gnu-hpc", rpm:"mpich-gnu-hpc~4.1.2~150600.3.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mpich-gnu-hpc-devel", rpm:"mpich-gnu-hpc-devel~4.1.2~150600.3.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mpich-gnu-hpc-devel-static", rpm:"mpich-gnu-hpc-devel-static~4.1.2~150600.3.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mpich-gnu-hpc-macros-devel", rpm:"mpich-gnu-hpc-macros-devel~4.1.2~150600.3.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mpich-ofi", rpm:"mpich-ofi~4.1.2~150600.3.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mpich-ofi-devel", rpm:"mpich-ofi-devel~4.1.2~150600.3.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mpich-ofi-gnu-hpc", rpm:"mpich-ofi-gnu-hpc~4.1.2~150600.3.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mpich-ofi-gnu-hpc-devel", rpm:"mpich-ofi-gnu-hpc-devel~4.1.2~150600.3.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mpich-ofi-gnu-hpc-devel-static", rpm:"mpich-ofi-gnu-hpc-devel-static~4.1.2~150600.3.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mpich-ofi-gnu-hpc-macros-devel", rpm:"mpich-ofi-gnu-hpc-macros-devel~4.1.2~150600.3.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mpich-ofi_4_0_2-gnu-hpc", rpm:"mpich-ofi_4_0_2-gnu-hpc~4.0.2~150500.3.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mpich-ofi_4_0_2-gnu-hpc-devel", rpm:"mpich-ofi_4_0_2-gnu-hpc-devel~4.0.2~150500.3.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mpich-ofi_4_0_2-gnu-hpc-devel-static", rpm:"mpich-ofi_4_0_2-gnu-hpc-devel-static~4.0.2~150500.3.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mpich-ofi_4_0_2-gnu-hpc-macros-devel", rpm:"mpich-ofi_4_0_2-gnu-hpc-macros-devel~4.0.2~150500.3.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mpich-ofi_4_1_2-gnu-hpc", rpm:"mpich-ofi_4_1_2-gnu-hpc~4.1.2~150600.3.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mpich-ofi_4_1_2-gnu-hpc-devel", rpm:"mpich-ofi_4_1_2-gnu-hpc-devel~4.1.2~150600.3.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mpich-ofi_4_1_2-gnu-hpc-devel-static", rpm:"mpich-ofi_4_1_2-gnu-hpc-devel-static~4.1.2~150600.3.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mpich-ofi_4_1_2-gnu-hpc-macros-devel", rpm:"mpich-ofi_4_1_2-gnu-hpc-macros-devel~4.1.2~150600.3.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mpich_4_0_2-gnu-hpc", rpm:"mpich_4_0_2-gnu-hpc~4.0.2~150500.3.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mpich_4_0_2-gnu-hpc-devel", rpm:"mpich_4_0_2-gnu-hpc-devel~4.0.2~150500.3.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mpich_4_0_2-gnu-hpc-devel-static", rpm:"mpich_4_0_2-gnu-hpc-devel-static~4.0.2~150500.3.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mpich_4_0_2-gnu-hpc-macros-devel", rpm:"mpich_4_0_2-gnu-hpc-macros-devel~4.0.2~150500.3.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mpich_4_1_2-gnu-hpc", rpm:"mpich_4_1_2-gnu-hpc~4.1.2~150600.3.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mpich_4_1_2-gnu-hpc-devel", rpm:"mpich_4_1_2-gnu-hpc-devel~4.1.2~150600.3.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mpich_4_1_2-gnu-hpc-devel-static", rpm:"mpich_4_1_2-gnu-hpc-devel-static~4.1.2~150600.3.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mpich_4_1_2-gnu-hpc-macros-devel", rpm:"mpich_4_1_2-gnu-hpc-macros-devel~4.1.2~150600.3.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvapich2", rpm:"mvapich2~2.3.7~150600.9.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvapich2-devel", rpm:"mvapich2-devel~2.3.7~150600.9.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvapich2-devel-static", rpm:"mvapich2-devel-static~2.3.7~150600.9.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvapich2-doc", rpm:"mvapich2-doc~2.3.7~150600.9.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvapich2-gnu-hpc", rpm:"mvapich2-gnu-hpc~2.3.7~150600.9.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvapich2-gnu-hpc-devel", rpm:"mvapich2-gnu-hpc-devel~2.3.7~150600.9.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvapich2-gnu-hpc-doc", rpm:"mvapich2-gnu-hpc-doc~2.3.7~150600.9.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvapich2-gnu-hpc-macros-devel", rpm:"mvapich2-gnu-hpc-macros-devel~2.3.7~150600.9.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvapich2-psm", rpm:"mvapich2-psm~2.3.7~150500.3.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvapich2-psm-devel", rpm:"mvapich2-psm-devel~2.3.7~150500.3.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvapich2-psm-devel-static", rpm:"mvapich2-psm-devel-static~2.3.7~150500.3.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvapich2-psm-doc", rpm:"mvapich2-psm-doc~2.3.7~150500.3.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvapich2-psm-gnu-hpc", rpm:"mvapich2-psm-gnu-hpc~2.3.7~150500.3.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvapich2-psm-gnu-hpc-devel", rpm:"mvapich2-psm-gnu-hpc-devel~2.3.7~150500.3.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvapich2-psm-gnu-hpc-doc", rpm:"mvapich2-psm-gnu-hpc-doc~2.3.7~150500.3.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvapich2-psm-gnu-hpc-macros-devel", rpm:"mvapich2-psm-gnu-hpc-macros-devel~2.3.7~150500.3.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvapich2-psm2", rpm:"mvapich2-psm2~2.3.7~150600.9.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvapich2-psm2-devel", rpm:"mvapich2-psm2-devel~2.3.7~150600.9.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvapich2-psm2-devel-static", rpm:"mvapich2-psm2-devel-static~2.3.7~150600.9.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvapich2-psm2-doc", rpm:"mvapich2-psm2-doc~2.3.7~150600.9.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvapich2-psm2-gnu-hpc", rpm:"mvapich2-psm2-gnu-hpc~2.3.7~150600.9.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvapich2-psm2-gnu-hpc-devel", rpm:"mvapich2-psm2-gnu-hpc-devel~2.3.7~150600.9.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvapich2-psm2-gnu-hpc-doc", rpm:"mvapich2-psm2-gnu-hpc-doc~2.3.7~150600.9.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvapich2-psm2-gnu-hpc-macros-devel", rpm:"mvapich2-psm2-gnu-hpc-macros-devel~2.3.7~150600.9.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvapich2-psm2_2_3_7-gnu-hpc", rpm:"mvapich2-psm2_2_3_7-gnu-hpc~2.3.7~150600.9.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvapich2-psm2_2_3_7-gnu-hpc-devel", rpm:"mvapich2-psm2_2_3_7-gnu-hpc-devel~2.3.7~150600.9.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvapich2-psm2_2_3_7-gnu-hpc-devel-static", rpm:"mvapich2-psm2_2_3_7-gnu-hpc-devel-static~2.3.7~150600.9.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvapich2-psm2_2_3_7-gnu-hpc-doc", rpm:"mvapich2-psm2_2_3_7-gnu-hpc-doc~2.3.7~150600.9.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvapich2-psm2_2_3_7-gnu-hpc-macros-devel", rpm:"mvapich2-psm2_2_3_7-gnu-hpc-macros-devel~2.3.7~150600.9.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvapich2-psm_2_3_7-gnu-hpc", rpm:"mvapich2-psm_2_3_7-gnu-hpc~2.3.7~150500.3.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvapich2-psm_2_3_7-gnu-hpc-devel", rpm:"mvapich2-psm_2_3_7-gnu-hpc-devel~2.3.7~150500.3.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvapich2-psm_2_3_7-gnu-hpc-devel-static", rpm:"mvapich2-psm_2_3_7-gnu-hpc-devel-static~2.3.7~150500.3.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvapich2-psm_2_3_7-gnu-hpc-doc", rpm:"mvapich2-psm_2_3_7-gnu-hpc-doc~2.3.7~150500.3.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvapich2-psm_2_3_7-gnu-hpc-macros-devel", rpm:"mvapich2-psm_2_3_7-gnu-hpc-macros-devel~2.3.7~150500.3.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvapich2_2_3_7-gnu-hpc", rpm:"mvapich2_2_3_7-gnu-hpc~2.3.7~150600.9.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvapich2_2_3_7-gnu-hpc-devel", rpm:"mvapich2_2_3_7-gnu-hpc-devel~2.3.7~150600.9.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvapich2_2_3_7-gnu-hpc-devel-static", rpm:"mvapich2_2_3_7-gnu-hpc-devel-static~2.3.7~150600.9.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvapich2_2_3_7-gnu-hpc-doc", rpm:"mvapich2_2_3_7-gnu-hpc-doc~2.3.7~150600.9.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvapich2_2_3_7-gnu-hpc-macros-devel", rpm:"mvapich2_2_3_7-gnu-hpc-macros-devel~2.3.7~150600.9.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openmpi4", rpm:"openmpi4~4.1.6~150600.3.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openmpi4-config", rpm:"openmpi4-config~4.1.6~150600.3.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openmpi4-devel", rpm:"openmpi4-devel~4.1.6~150600.3.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openmpi4-docs", rpm:"openmpi4-docs~4.1.6~150600.3.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openmpi4-gnu-hpc", rpm:"openmpi4-gnu-hpc~4.1.6~150600.3.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openmpi4-gnu-hpc-devel", rpm:"openmpi4-gnu-hpc-devel~4.1.6~150600.3.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openmpi4-gnu-hpc-devel-static", rpm:"openmpi4-gnu-hpc-devel-static~4.1.6~150600.3.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openmpi4-gnu-hpc-docs", rpm:"openmpi4-gnu-hpc-docs~4.1.6~150600.3.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openmpi4-gnu-hpc-macros-devel", rpm:"openmpi4-gnu-hpc-macros-devel~4.1.6~150600.3.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openmpi4-libs-32bit", rpm:"openmpi4-libs-32bit~4.1.6~150600.3.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openmpi4-libs", rpm:"openmpi4-libs~4.1.6~150600.3.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openmpi4-macros-devel", rpm:"openmpi4-macros-devel~4.1.6~150600.3.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openmpi4-testsuite", rpm:"openmpi4-testsuite~4.1.6~150600.3.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openmpi_4_1_4-gnu-hpc", rpm:"openmpi_4_1_4-gnu-hpc~4.1.4~150500.3.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openmpi_4_1_4-gnu-hpc-devel", rpm:"openmpi_4_1_4-gnu-hpc-devel~4.1.4~150500.3.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openmpi_4_1_4-gnu-hpc-devel-static", rpm:"openmpi_4_1_4-gnu-hpc-devel-static~4.1.4~150500.3.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openmpi_4_1_4-gnu-hpc-docs", rpm:"openmpi_4_1_4-gnu-hpc-docs~4.1.4~150500.3.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openmpi_4_1_4-gnu-hpc-macros-devel", rpm:"openmpi_4_1_4-gnu-hpc-macros-devel~4.1.4~150500.3.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openmpi_4_1_4-gnu-hpc-testsuite", rpm:"openmpi_4_1_4-gnu-hpc-testsuite~4.1.4~150500.3.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openmpi_4_1_6-gnu-hpc", rpm:"openmpi_4_1_6-gnu-hpc~4.1.6~150600.3.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openmpi_4_1_6-gnu-hpc-devel", rpm:"openmpi_4_1_6-gnu-hpc-devel~4.1.6~150600.3.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openmpi_4_1_6-gnu-hpc-devel-static", rpm:"openmpi_4_1_6-gnu-hpc-devel-static~4.1.6~150600.3.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openmpi_4_1_6-gnu-hpc-docs", rpm:"openmpi_4_1_6-gnu-hpc-docs~4.1.6~150600.3.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openmpi_4_1_6-gnu-hpc-macros-devel", rpm:"openmpi_4_1_6-gnu-hpc-macros-devel~4.1.6~150600.3.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openmpi_4_1_6-gnu-hpc-testsuite", rpm:"openmpi_4_1_6-gnu-hpc-testsuite~4.1.6~150600.3.2.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pmix", rpm:"pmix~3.2.3~150300.3.10.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pmix-devel", rpm:"pmix-devel~3.2.3~150300.3.10.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pmix-headers", rpm:"pmix-headers~3.2.3~150300.3.10.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pmix-mca-params", rpm:"pmix-mca-params~3.2.3~150300.3.10.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pmix-plugin-munge", rpm:"pmix-plugin-munge~3.2.3~150300.3.10.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pmix-plugins", rpm:"pmix-plugins~3.2.3~150300.3.10.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pmix-test", rpm:"pmix-test~3.2.3~150300.3.10.1", rls:"openSUSELeap15.6"))) {
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
