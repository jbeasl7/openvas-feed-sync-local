# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856445");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2016-4332", "CVE-2017-17507", "CVE-2018-11202", "CVE-2018-11205", "CVE-2019-8396", "CVE-2020-10812", "CVE-2021-37501", "CVE-2024-29158", "CVE-2024-29161", "CVE-2024-29166", "CVE-2024-32608", "CVE-2024-32610", "CVE-2024-32614", "CVE-2024-32619", "CVE-2024-32620", "CVE-2024-33873", "CVE-2024-33874", "CVE-2024-33875");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-17 16:47:02 +0000 (Thu, 17 Oct 2024)");
  script_tag(name:"creation_date", value:"2024-09-07 04:00:39 +0000 (Sat, 07 Sep 2024)");
  script_name("openSUSE: Security Advisory for hdf5, netcdf, trilinos (SUSE-SU-2024:3144-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.3");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3144-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/7OFTEFNAJPV4UBTWDWNQRFMOYIVUMAX5");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'hdf5, netcdf, trilinos'
  package(s) announced via the SUSE-SU-2024:3144-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for hdf5, netcdf, trilinos fixes the following issues:

  hdf5 was updated from version 1.10.8 to 1.10.11:

  * Security issues fixed:

  * CVE-2019-8396: Fixed problems with malformed HDF5 files where content does
      not match expected size. (bsc#1125882)

  * CVE-2018-11202: Fixed that a malformed file could result in chunk index
      memory leaks. (bsc#1093641)

  * CVE-2016-4332: Fixed an assertion in a previous fix for this issue
      (bsc#1011205).

  * CVE-2020-10812: Fixed a segfault on file close in h5debug which fails with a
      core dump on a file that has an illegal file size in its cache image.Fixes
      HDFFV-11052, (bsc#1167400).

  * CVE-2021-37501: Fixed buffer overflow in hdf5-h5dump (bsc#1207973)

  * Other security issues fixed (bsc#1224158):

  * CVE-2024-29158, CVE-2024-29161, CVE-2024-29166, CVE-2024-32608,

  * CVE-2024-32610, CVE-2024-32614, CVE-2024-32619, CVE-2024-32620,

  * CVE-2024-33873, CVE-2024-33874, CVE-2024-33875

  * Additionally, these fixes resolve crashes triggered by the reproducers for CVE-2017-17507, CVE-2018-11205. These crashes appear to be unrelated to the original problems

  * Other issues fixed:

  * Remove timestamp/buildhost/kernel version from libhdf5.settings
      (bsc#1209548)

  * Changed the error handling for a not found path in the find plugin process.

  * Fixed a file space allocation bug in the parallel library for chunked
      datasets.

  * Fixed an assertion failure in Parallel HDF5 when a file can't be created due
      to an invalid library version bounds setting.

  * Fixed memory leaks that could occur when reading a dataset from a malformed
      file.

  * Fixed a bug in H5Ocopy that could generate invalid HDF5 files

  * Fixed potential heap buffer overflow in decoding of link info message.

  * Fixed potential buffer overrun issues in some object header decode routines.

  * Fixed a heap buffer overflow that occurs when reading from a dataset with a
      compact layout within a malformed HDF5 file.

  * Fixed memory leak when running h5dump with proof of vulnerability file.

  * Added option --no-compact-subset to h5diff

  * Several improvements to parallel compression feature, including:

  * Improved support for collective I/O (for both writes and reads).

  * Reduction of copying of application data buffers passed to H5Dwrite.

  * Addition of support for incremental file space allocation for filtered datasets created in parallel.

  * Addition of support for HDF5's 'don't filter partial edge chunks' flag

  * Additio ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'hdf5, netcdf, trilinos' package(s) on openSUSE Leap 15.3.");

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

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"hdf5-gnu-mpich-hpc", rpm:"hdf5-gnu-mpich-hpc~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5-gnu-openmpi3-hpc-devel", rpm:"hdf5-gnu-openmpi3-hpc-devel~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5-gnu-hpc", rpm:"hdf5-gnu-hpc~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-gnu-openmpi3-hpc-devel", rpm:"netcdf-gnu-openmpi3-hpc-devel~4.7.4~150300.4.7.17", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5-gnu-openmpi4-hpc", rpm:"hdf5-gnu-openmpi4-hpc~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5-gnu-openmpi4-hpc-devel", rpm:"hdf5-gnu-openmpi4-hpc-devel~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-gnu-mpich-hpc-devel", rpm:"netcdf-gnu-mpich-hpc-devel~4.7.4~150300.4.7.19", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-gnu-openmpi2-hpc", rpm:"netcdf-gnu-openmpi2-hpc~4.7.4~150300.4.7.10", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5-hpc-examples", rpm:"hdf5-hpc-examples~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"adios-gnu-mvapich2-hpc-devel-static", rpm:"adios-gnu-mvapich2-hpc-devel-static~1.13.1~150300.12.4.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5-gnu-mvapich2-hpc-devel", rpm:"hdf5-gnu-mvapich2-hpc-devel~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-gnu-hpc", rpm:"netcdf-gnu-hpc~4.7.4~150300.4.7.19", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-gnu-mvapich2-hpc-devel", rpm:"netcdf-gnu-mvapich2-hpc-devel~4.7.4~150300.4.7.20", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"trilinos-gnu-openmpi4-hpc-devel", rpm:"trilinos-gnu-openmpi4-hpc-devel~13.2.0~150300.3.12.18", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"adios-gnu-mpich-hpc-devel-static", rpm:"adios-gnu-mpich-hpc-devel-static~1.13.1~150300.12.4.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-gnu-hpc-devel", rpm:"netcdf-gnu-hpc-devel~4.7.4~150300.4.7.19", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-gnu-openmpi3-hpc", rpm:"netcdf-gnu-openmpi3-hpc~4.7.4~150300.4.7.17", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"adios-gnu-mpich-hpc-devel", rpm:"adios-gnu-mpich-hpc-devel~1.13.1~150300.12.4.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5-gnu-hpc-devel", rpm:"hdf5-gnu-hpc-devel~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"adios-gnu-openmpi3-hpc", rpm:"adios-gnu-openmpi3-hpc~1.13.1~150300.12.4.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"adios-gnu-openmpi2-hpc-devel-static", rpm:"adios-gnu-openmpi2-hpc-devel-static~1.13.1~150300.12.4.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"adios-gnu-openmpi4-hpc-devel-static", rpm:"adios-gnu-openmpi4-hpc-devel-static~1.13.1~150300.12.4.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"adios-gnu-mvapich2-hpc-devel", rpm:"adios-gnu-mvapich2-hpc-devel~1.13.1~150300.12.4.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"adios-gnu-openmpi2-hpc", rpm:"adios-gnu-openmpi2-hpc~1.13.1~150300.12.4.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"petsc-doc", rpm:"petsc-doc~3.14.5~150300.3.4.3", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"trilinos-gnu-openmpi2-hpc-devel", rpm:"trilinos-gnu-openmpi2-hpc-devel~13.2.0~150300.3.12.9", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"adios-gnu-mvapich2-hpc", rpm:"adios-gnu-mvapich2-hpc~1.13.1~150300.12.4.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-gnu-mvapich2-hpc", rpm:"netcdf-gnu-mvapich2-hpc~4.7.4~150300.4.7.20", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-gnu-openmpi4-hpc-devel", rpm:"netcdf-gnu-openmpi4-hpc-devel~4.7.4~150300.4.7.21", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"trilinos-hpc-doc", rpm:"trilinos-hpc-doc~13.2.0~150300.3.12.9", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"trilinos-gnu-mpich-hpc-devel", rpm:"trilinos-gnu-mpich-hpc-devel~13.2.0~150300.3.12.18", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"adios-gnu-mpich-hpc", rpm:"adios-gnu-mpich-hpc~1.13.1~150300.12.4.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"trilinos-gnu-mvapich2-hpc-devel", rpm:"trilinos-gnu-mvapich2-hpc-devel~13.2.0~150300.3.12.18", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-gnu-mpich-hpc", rpm:"netcdf-gnu-mpich-hpc~4.7.4~150300.4.7.19", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"adios-gnu-openmpi4-hpc", rpm:"adios-gnu-openmpi4-hpc~1.13.1~150300.12.4.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5-gnu-openmpi3-hpc", rpm:"hdf5-gnu-openmpi3-hpc~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5-gnu-mpich-hpc-devel", rpm:"hdf5-gnu-mpich-hpc-devel~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"adios-gnu-openmpi2-hpc-devel", rpm:"adios-gnu-openmpi2-hpc-devel~1.13.1~150300.12.4.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-gnu-openmpi2-hpc-devel", rpm:"netcdf-gnu-openmpi2-hpc-devel~4.7.4~150300.4.7.10", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"trilinos-gnu-openmpi3-hpc-devel", rpm:"trilinos-gnu-openmpi3-hpc-devel~13.2.0~150300.3.12.16", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"adios-gnu-openmpi3-hpc-devel-static", rpm:"adios-gnu-openmpi3-hpc-devel-static~1.13.1~150300.12.4.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-gnu-openmpi4-hpc", rpm:"netcdf-gnu-openmpi4-hpc~4.7.4~150300.4.7.21", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"trilinos_13_2_0-hpc-doc", rpm:"trilinos_13_2_0-hpc-doc~13.2.0~150300.3.12.9", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5-gnu-mvapich2-hpc", rpm:"hdf5-gnu-mvapich2-hpc~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"adios-gnu-openmpi4-hpc-devel", rpm:"adios-gnu-openmpi4-hpc-devel~1.13.1~150300.12.4.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"adios-gnu-openmpi3-hpc-devel", rpm:"adios-gnu-openmpi3-hpc-devel~1.13.1~150300.12.4.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"petsc_3_14_5-gnu-mpich-hpc-debugsource", rpm:"petsc_3_14_5-gnu-mpich-hpc-debugsource~3.14.5~150300.3.4.4", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"adios_1_13_1-gnu-openmpi2-hpc-debuginfo", rpm:"adios_1_13_1-gnu-openmpi2-hpc-debuginfo~1.13.1~150300.12.4.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"adios_1_13_1-gnu-openmpi3-hpc", rpm:"adios_1_13_1-gnu-openmpi3-hpc~1.13.1~150300.12.4.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpetsc_3_14_5-gnu-openmpi4-hpc", rpm:"libpetsc_3_14_5-gnu-openmpi4-hpc~3.14.5~150300.3.4.4", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"petsc_3_14_5-gnu-openmpi4-hpc-debugsource", rpm:"petsc_3_14_5-gnu-openmpi4-hpc-debugsource~3.14.5~150300.3.4.4", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpetsc_3_14_5-gnu-openmpi2-hpc-debuginfo", rpm:"libpetsc_3_14_5-gnu-openmpi2-hpc-debuginfo~3.14.5~150300.3.4.4", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"petsc-gnu-openmpi4-hpc-devel", rpm:"petsc-gnu-openmpi4-hpc-devel~3.14.5~150300.3.4.4", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"adios_1_13_1-gnu-openmpi3-hpc-devel", rpm:"adios_1_13_1-gnu-openmpi3-hpc-devel~1.13.1~150300.12.4.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"petsc-gnu-mvapich2-hpc-devel", rpm:"petsc-gnu-mvapich2-hpc-devel~3.14.5~150300.3.4.4", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"petsc_3_14_5-gnu-mpich-hpc-devel", rpm:"petsc_3_14_5-gnu-mpich-hpc-devel~3.14.5~150300.3.4.4", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"petsc-gnu-mpich-hpc-devel", rpm:"petsc-gnu-mpich-hpc-devel~3.14.5~150300.3.4.4", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"adios_1_13_1-gnu-openmpi4-hpc-debugsource", rpm:"adios_1_13_1-gnu-openmpi4-hpc-debugsource~1.13.1~150300.12.4.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpetsc_3_14_5-gnu-mvapich2-hpc", rpm:"libpetsc_3_14_5-gnu-mvapich2-hpc~3.14.5~150300.3.4.4", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpetsc_3_14_5-gnu-openmpi3-hpc", rpm:"libpetsc_3_14_5-gnu-openmpi3-hpc~3.14.5~150300.3.4.4", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"adios_1_13_1-gnu-openmpi4-hpc-devel-static", rpm:"adios_1_13_1-gnu-openmpi4-hpc-devel-static~1.13.1~150300.12.4.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"adios_1_13_1-gnu-openmpi4-hpc", rpm:"adios_1_13_1-gnu-openmpi4-hpc~1.13.1~150300.12.4.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"adios_1_13_1-gnu-mvapich2-hpc-devel", rpm:"adios_1_13_1-gnu-mvapich2-hpc-devel~1.13.1~150300.12.4.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"petsc_3_14_5-gnu-openmpi2-hpc-devel", rpm:"petsc_3_14_5-gnu-openmpi2-hpc-devel~3.14.5~150300.3.4.4", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"petsc_3_14_5-gnu-openmpi3-hpc-debugsource", rpm:"petsc_3_14_5-gnu-openmpi3-hpc-debugsource~3.14.5~150300.3.4.4", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"adios_1_13_1-gnu-openmpi4-hpc-devel", rpm:"adios_1_13_1-gnu-openmpi4-hpc-devel~1.13.1~150300.12.4.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"petsc_3_14_5-gnu-openmpi3-hpc-devel", rpm:"petsc_3_14_5-gnu-openmpi3-hpc-devel~3.14.5~150300.3.4.4", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"adios_1_13_1-gnu-mvapich2-hpc", rpm:"adios_1_13_1-gnu-mvapich2-hpc~1.13.1~150300.12.4.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpetsc-gnu-mpich-hpc", rpm:"libpetsc-gnu-mpich-hpc~3.14.5~150300.3.4.4", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpetsc_3_14_5-gnu-mpich-hpc", rpm:"libpetsc_3_14_5-gnu-mpich-hpc~3.14.5~150300.3.4.4", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpetsc_3_14_5-gnu-openmpi3-hpc-debuginfo", rpm:"libpetsc_3_14_5-gnu-openmpi3-hpc-debuginfo~3.14.5~150300.3.4.4", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"petsc_3_14_5-gnu-openmpi3-hpc-saws", rpm:"petsc_3_14_5-gnu-openmpi3-hpc-saws~3.14.5~150300.3.4.4", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"adios_1_13_1-gnu-openmpi3-hpc-debuginfo", rpm:"adios_1_13_1-gnu-openmpi3-hpc-debuginfo~1.13.1~150300.12.4.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"adios_1_13_1-gnu-mpich-hpc-devel", rpm:"adios_1_13_1-gnu-mpich-hpc-devel~1.13.1~150300.12.4.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"adios_1_13_1-gnu-mpich-hpc-debugsource", rpm:"adios_1_13_1-gnu-mpich-hpc-debugsource~1.13.1~150300.12.4.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpetsc-gnu-openmpi3-hpc", rpm:"libpetsc-gnu-openmpi3-hpc~3.14.5~150300.3.4.4", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"petsc-gnu-openmpi2-hpc-devel", rpm:"petsc-gnu-openmpi2-hpc-devel~3.14.5~150300.3.4.4", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"adios_1_13_1-gnu-openmpi2-hpc-debugsource", rpm:"adios_1_13_1-gnu-openmpi2-hpc-debugsource~1.13.1~150300.12.4.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"petsc_3_14_5-gnu-openmpi4-hpc-devel", rpm:"petsc_3_14_5-gnu-openmpi4-hpc-devel~3.14.5~150300.3.4.4", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"petsc_3_14_5-gnu-mvapich2-hpc-debugsource", rpm:"petsc_3_14_5-gnu-mvapich2-hpc-debugsource~3.14.5~150300.3.4.4", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpetsc-gnu-openmpi4-hpc", rpm:"libpetsc-gnu-openmpi4-hpc~3.14.5~150300.3.4.4", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"adios_1_13_1-gnu-mvapich2-hpc-debuginfo", rpm:"adios_1_13_1-gnu-mvapich2-hpc-debuginfo~1.13.1~150300.12.4.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"adios_1_13_1-gnu-mpich-hpc-devel-static", rpm:"adios_1_13_1-gnu-mpich-hpc-devel-static~1.13.1~150300.12.4.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"petsc_3_14_5-gnu-openmpi2-hpc-saws", rpm:"petsc_3_14_5-gnu-openmpi2-hpc-saws~3.14.5~150300.3.4.4", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"petsc-gnu-openmpi3-hpc-devel", rpm:"petsc-gnu-openmpi3-hpc-devel~3.14.5~150300.3.4.4", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpetsc_3_14_5-gnu-mpich-hpc-debuginfo", rpm:"libpetsc_3_14_5-gnu-mpich-hpc-debuginfo~3.14.5~150300.3.4.4", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpetsc_3_14_5-gnu-openmpi2-hpc", rpm:"libpetsc_3_14_5-gnu-openmpi2-hpc~3.14.5~150300.3.4.4", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"adios_1_13_1-gnu-openmpi2-hpc-devel", rpm:"adios_1_13_1-gnu-openmpi2-hpc-devel~1.13.1~150300.12.4.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"adios_1_13_1-gnu-mpich-hpc-debuginfo", rpm:"adios_1_13_1-gnu-mpich-hpc-debuginfo~1.13.1~150300.12.4.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpetsc_3_14_5-gnu-mvapich2-hpc-debuginfo", rpm:"libpetsc_3_14_5-gnu-mvapich2-hpc-debuginfo~3.14.5~150300.3.4.4", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"adios_1_13_1-gnu-openmpi4-hpc-debuginfo", rpm:"adios_1_13_1-gnu-openmpi4-hpc-debuginfo~1.13.1~150300.12.4.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"adios_1_13_1-gnu-openmpi3-hpc-debugsource", rpm:"adios_1_13_1-gnu-openmpi3-hpc-debugsource~1.13.1~150300.12.4.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"adios_1_13_1-gnu-mpich-hpc", rpm:"adios_1_13_1-gnu-mpich-hpc~1.13.1~150300.12.4.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"petsc_3_14_5-gnu-mvapich2-hpc-saws", rpm:"petsc_3_14_5-gnu-mvapich2-hpc-saws~3.14.5~150300.3.4.4", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpetsc-gnu-openmpi2-hpc", rpm:"libpetsc-gnu-openmpi2-hpc~3.14.5~150300.3.4.4", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpetsc-gnu-mvapich2-hpc", rpm:"libpetsc-gnu-mvapich2-hpc~3.14.5~150300.3.4.4", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"adios_1_13_1-gnu-openmpi2-hpc-devel-static", rpm:"adios_1_13_1-gnu-openmpi2-hpc-devel-static~1.13.1~150300.12.4.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"adios_1_13_1-gnu-openmpi3-hpc-devel-static", rpm:"adios_1_13_1-gnu-openmpi3-hpc-devel-static~1.13.1~150300.12.4.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"adios_1_13_1-gnu-mvapich2-hpc-devel-static", rpm:"adios_1_13_1-gnu-mvapich2-hpc-devel-static~1.13.1~150300.12.4.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"adios_1_13_1-gnu-mvapich2-hpc-debugsource", rpm:"adios_1_13_1-gnu-mvapich2-hpc-debugsource~1.13.1~150300.12.4.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"petsc_3_14_5-gnu-openmpi4-hpc-saws", rpm:"petsc_3_14_5-gnu-openmpi4-hpc-saws~3.14.5~150300.3.4.4", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpetsc_3_14_5-gnu-openmpi4-hpc-debuginfo", rpm:"libpetsc_3_14_5-gnu-openmpi4-hpc-debuginfo~3.14.5~150300.3.4.4", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"petsc_3_14_5-gnu-mvapich2-hpc-devel", rpm:"petsc_3_14_5-gnu-mvapich2-hpc-devel~3.14.5~150300.3.4.4", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"adios_1_13_1-gnu-openmpi2-hpc", rpm:"adios_1_13_1-gnu-openmpi2-hpc~1.13.1~150300.12.4.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"petsc_3_14_5-gnu-mpich-hpc-saws", rpm:"petsc_3_14_5-gnu-mpich-hpc-saws~3.14.5~150300.3.4.4", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"petsc_3_14_5-gnu-openmpi2-hpc-debugsource", rpm:"petsc_3_14_5-gnu-openmpi2-hpc-debugsource~3.14.5~150300.3.4.4", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf_4_7_4-gnu-openmpi4-hpc-debuginfo", rpm:"libnetcdf_4_7_4-gnu-openmpi4-hpc-debuginfo~4.7.4~150300.4.7.21", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-debuginfo", rpm:"netcdf-debuginfo~4.7.4~150300.4.7.9", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf18", rpm:"libnetcdf18~4.7.4~150300.4.7.9", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-openmpi3-devel-static", rpm:"netcdf-openmpi3-devel-static~4.7.4~150300.4.7.9", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf-gnu-openmpi4-hpc", rpm:"libnetcdf-gnu-openmpi4-hpc~4.7.4~150300.4.7.21", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-openmpi3-hpc-debugsource", rpm:"netcdf_4_7_4-gnu-openmpi3-hpc-debugsource~4.7.4~150300.4.7.17", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-hpc", rpm:"netcdf_4_7_4-gnu-hpc~4.7.4~150300.4.7.19", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-openmpi4-hpc-debugsource", rpm:"netcdf_4_7_4-gnu-openmpi4-hpc-debugsource~4.7.4~150300.4.7.21", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-openmpi4", rpm:"netcdf-openmpi4~4.7.4~150300.4.7.9", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-openmpi2", rpm:"netcdf-openmpi2~4.7.4~150300.4.7.9", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-devel-data", rpm:"netcdf-devel-data~4.7.4~150300.4.7.9", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf_4_7_4-gnu-mpich-hpc-debuginfo", rpm:"libnetcdf_4_7_4-gnu-mpich-hpc-debuginfo~4.7.4~150300.4.7.19", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-openmpi4-debuginfo", rpm:"netcdf-openmpi4-debuginfo~4.7.4~150300.4.7.9", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf_4_7_4-gnu-mvapich2-hpc-debuginfo", rpm:"libnetcdf_4_7_4-gnu-mvapich2-hpc-debuginfo~4.7.4~150300.4.7.20", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf-gnu-hpc", rpm:"libnetcdf-gnu-hpc~4.7.4~150300.4.7.19", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-openmpi3-debuginfo", rpm:"netcdf-openmpi3-debuginfo~4.7.4~150300.4.7.9", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-openmpi3-hpc-debuginfo", rpm:"netcdf_4_7_4-gnu-openmpi3-hpc-debuginfo~4.7.4~150300.4.7.17", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-openmpi4-hpc-debuginfo", rpm:"netcdf_4_7_4-gnu-openmpi4-hpc-debuginfo~4.7.4~150300.4.7.21", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-openmpi3-devel", rpm:"netcdf-openmpi3-devel~4.7.4~150300.4.7.9", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf18-openmpi4-debuginfo", rpm:"libnetcdf18-openmpi4-debuginfo~4.7.4~150300.4.7.9", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-openmpi2-hpc-devel-static", rpm:"netcdf_4_7_4-gnu-openmpi2-hpc-devel-static~4.7.4~150300.4.7.10", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf18-openmpi4", rpm:"libnetcdf18-openmpi4~4.7.4~150300.4.7.9", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-openmpi2-hpc-debugsource", rpm:"netcdf_4_7_4-gnu-openmpi2-hpc-debugsource~4.7.4~150300.4.7.10", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf_4_7_4-gnu-openmpi3-hpc", rpm:"libnetcdf_4_7_4-gnu-openmpi3-hpc~4.7.4~150300.4.7.17", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-openmpi3-hpc", rpm:"netcdf_4_7_4-gnu-openmpi3-hpc~4.7.4~150300.4.7.17", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-openmpi3-hpc-devel", rpm:"netcdf_4_7_4-gnu-openmpi3-hpc-devel~4.7.4~150300.4.7.17", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-openmpi4-hpc-devel-static", rpm:"netcdf_4_7_4-gnu-openmpi4-hpc-devel-static~4.7.4~150300.4.7.21", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-mpich-hpc-devel-debuginfo", rpm:"netcdf_4_7_4-gnu-mpich-hpc-devel-debuginfo~4.7.4~150300.4.7.19", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-openmpi4-hpc-devel-debuginfo", rpm:"netcdf_4_7_4-gnu-openmpi4-hpc-devel-debuginfo~4.7.4~150300.4.7.21", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf18-openmpi3", rpm:"libnetcdf18-openmpi3~4.7.4~150300.4.7.9", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf-gnu-mpich-hpc", rpm:"libnetcdf-gnu-mpich-hpc~4.7.4~150300.4.7.19", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf_4_7_4-gnu-hpc-debuginfo", rpm:"libnetcdf_4_7_4-gnu-hpc-debuginfo~4.7.4~150300.4.7.19", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-hpc-debuginfo", rpm:"netcdf_4_7_4-gnu-hpc-debuginfo~4.7.4~150300.4.7.19", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf-gnu-openmpi3-hpc", rpm:"libnetcdf-gnu-openmpi3-hpc~4.7.4~150300.4.7.17", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-mvapich2-hpc-devel-static", rpm:"netcdf_4_7_4-gnu-mvapich2-hpc-devel-static~4.7.4~150300.4.7.20", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-openmpi2-debuginfo", rpm:"netcdf-openmpi2-debuginfo~4.7.4~150300.4.7.9", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-openmpi2-hpc", rpm:"netcdf_4_7_4-gnu-openmpi2-hpc~4.7.4~150300.4.7.10", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-openmpi4-devel-debuginfo", rpm:"netcdf-openmpi4-devel-debuginfo~4.7.4~150300.4.7.9", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf_4_7_4-gnu-openmpi2-hpc", rpm:"libnetcdf_4_7_4-gnu-openmpi2-hpc~4.7.4~150300.4.7.10", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf_4_7_4-gnu-openmpi2-hpc-debuginfo", rpm:"libnetcdf_4_7_4-gnu-openmpi2-hpc-debuginfo~4.7.4~150300.4.7.10", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-openmpi2-hpc-devel", rpm:"netcdf_4_7_4-gnu-openmpi2-hpc-devel~4.7.4~150300.4.7.10", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-mpich-hpc-devel", rpm:"netcdf_4_7_4-gnu-mpich-hpc-devel~4.7.4~150300.4.7.19", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-openmpi2-hpc-debuginfo", rpm:"netcdf_4_7_4-gnu-openmpi2-hpc-debuginfo~4.7.4~150300.4.7.10", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-mpich-hpc-devel-static", rpm:"netcdf_4_7_4-gnu-mpich-hpc-devel-static~4.7.4~150300.4.7.19", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-mvapich2-hpc", rpm:"netcdf_4_7_4-gnu-mvapich2-hpc~4.7.4~150300.4.7.20", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-openmpi4-devel-static", rpm:"netcdf-openmpi4-devel-static~4.7.4~150300.4.7.9", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-mpich-hpc-debugsource", rpm:"netcdf_4_7_4-gnu-mpich-hpc-debugsource~4.7.4~150300.4.7.19", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-openmpi3", rpm:"netcdf-openmpi3~4.7.4~150300.4.7.9", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-openmpi3-devel-debuginfo", rpm:"netcdf-openmpi3-devel-debuginfo~4.7.4~150300.4.7.9", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf18-openmpi3-debuginfo", rpm:"libnetcdf18-openmpi3-debuginfo~4.7.4~150300.4.7.9", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-openmpi2-devel-debuginfo", rpm:"netcdf-openmpi2-devel-debuginfo~4.7.4~150300.4.7.9", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-hpc-devel-static", rpm:"netcdf_4_7_4-gnu-hpc-devel-static~4.7.4~150300.4.7.19", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf18-openmpi2-debuginfo", rpm:"libnetcdf18-openmpi2-debuginfo~4.7.4~150300.4.7.9", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-openmpi3-debugsource", rpm:"netcdf-openmpi3-debugsource~4.7.4~150300.4.7.9", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-openmpi3-hpc-devel-debuginfo", rpm:"netcdf_4_7_4-gnu-openmpi3-hpc-devel-debuginfo~4.7.4~150300.4.7.17", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-devel", rpm:"netcdf-devel~4.7.4~150300.4.7.9", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-mvapich2-hpc-debuginfo", rpm:"netcdf_4_7_4-gnu-mvapich2-hpc-debuginfo~4.7.4~150300.4.7.20", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-devel-debuginfo", rpm:"netcdf-devel-debuginfo~4.7.4~150300.4.7.9", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-hpc-devel", rpm:"netcdf_4_7_4-gnu-hpc-devel~4.7.4~150300.4.7.19", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-openmpi4-hpc", rpm:"netcdf_4_7_4-gnu-openmpi4-hpc~4.7.4~150300.4.7.21", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-openmpi2-debugsource", rpm:"netcdf-openmpi2-debugsource~4.7.4~150300.4.7.9", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf_4_7_4-gnu-hpc", rpm:"libnetcdf_4_7_4-gnu-hpc~4.7.4~150300.4.7.19", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-mvapich2-hpc-devel-debuginfo", rpm:"netcdf_4_7_4-gnu-mvapich2-hpc-devel-debuginfo~4.7.4~150300.4.7.20", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf-gnu-openmpi2-hpc", rpm:"libnetcdf-gnu-openmpi2-hpc~4.7.4~150300.4.7.10", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-openmpi4-devel", rpm:"netcdf-openmpi4-devel~4.7.4~150300.4.7.9", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-mpich-hpc-debuginfo", rpm:"netcdf_4_7_4-gnu-mpich-hpc-debuginfo~4.7.4~150300.4.7.19", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf-gnu-mvapich2-hpc", rpm:"libnetcdf-gnu-mvapich2-hpc~4.7.4~150300.4.7.20", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf18-openmpi2", rpm:"libnetcdf18-openmpi2~4.7.4~150300.4.7.9", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-openmpi3-hpc-devel-static", rpm:"netcdf_4_7_4-gnu-openmpi3-hpc-devel-static~4.7.4~150300.4.7.17", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-devel-static", rpm:"netcdf-devel-static~4.7.4~150300.4.7.9", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-openmpi2-hpc-devel-debuginfo", rpm:"netcdf_4_7_4-gnu-openmpi2-hpc-devel-debuginfo~4.7.4~150300.4.7.10", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf_4_7_4-gnu-mvapich2-hpc", rpm:"libnetcdf_4_7_4-gnu-mvapich2-hpc~4.7.4~150300.4.7.20", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-hpc-devel-debuginfo", rpm:"netcdf_4_7_4-gnu-hpc-devel-debuginfo~4.7.4~150300.4.7.19", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf_4_7_4-gnu-mpich-hpc", rpm:"libnetcdf_4_7_4-gnu-mpich-hpc~4.7.4~150300.4.7.19", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-mpich-hpc", rpm:"netcdf_4_7_4-gnu-mpich-hpc~4.7.4~150300.4.7.19", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-openmpi2-devel", rpm:"netcdf-openmpi2-devel~4.7.4~150300.4.7.9", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-openmpi2-devel-static", rpm:"netcdf-openmpi2-devel-static~4.7.4~150300.4.7.9", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-hpc-debugsource", rpm:"netcdf_4_7_4-gnu-hpc-debugsource~4.7.4~150300.4.7.19", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf", rpm:"netcdf~4.7.4~150300.4.7.9", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-debugsource", rpm:"netcdf-debugsource~4.7.4~150300.4.7.9", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf_4_7_4-gnu-openmpi4-hpc", rpm:"libnetcdf_4_7_4-gnu-openmpi4-hpc~4.7.4~150300.4.7.21", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-mvapich2-hpc-debugsource", rpm:"netcdf_4_7_4-gnu-mvapich2-hpc-debugsource~4.7.4~150300.4.7.20", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-mvapich2-hpc-devel", rpm:"netcdf_4_7_4-gnu-mvapich2-hpc-devel~4.7.4~150300.4.7.20", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-openmpi4-debugsource", rpm:"netcdf-openmpi4-debugsource~4.7.4~150300.4.7.9", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-openmpi4-hpc-devel", rpm:"netcdf_4_7_4-gnu-openmpi4-hpc-devel~4.7.4~150300.4.7.21", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf18-debuginfo", rpm:"libnetcdf18-debuginfo~4.7.4~150300.4.7.9", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf_4_7_4-gnu-openmpi3-hpc-debuginfo", rpm:"libnetcdf_4_7_4-gnu-openmpi3-hpc-debuginfo~4.7.4~150300.4.7.17", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf18-openmpi3-32bit", rpm:"libnetcdf18-openmpi3-32bit~4.7.4~150300.4.7.9", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf18-32bit", rpm:"libnetcdf18-32bit~4.7.4~150300.4.7.9", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf18-32bit-debuginfo", rpm:"libnetcdf18-32bit-debuginfo~4.7.4~150300.4.7.9", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf18-openmpi2-32bit", rpm:"libnetcdf18-openmpi2-32bit~4.7.4~150300.4.7.9", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf18-openmpi4-32bit", rpm:"libnetcdf18-openmpi4-32bit~4.7.4~150300.4.7.9", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf18-openmpi4-32bit-debuginfo", rpm:"libnetcdf18-openmpi4-32bit-debuginfo~4.7.4~150300.4.7.9", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf18-openmpi2-32bit-debuginfo", rpm:"libnetcdf18-openmpi2-32bit-debuginfo~4.7.4~150300.4.7.9", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf18-openmpi3-32bit-debuginfo", rpm:"libnetcdf18-openmpi3-32bit-debuginfo~4.7.4~150300.4.7.9", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-openmpi4-hpc-debugsource", rpm:"hdf5_1_10_11-gnu-openmpi4-hpc-debugsource~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-openmpi4-hpc-debuginfo", rpm:"hdf5_1_10_11-gnu-openmpi4-hpc-debuginfo~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_1_10_11-gnu-mvapich2-hpc", rpm:"libhdf5_1_10_11-gnu-mvapich2-hpc~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-mvapich2-hpc", rpm:"hdf5_1_10_11-gnu-mvapich2-hpc~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5hl_fortran_1_10_11-gnu-mvapich2-hpc-debuginfo", rpm:"libhdf5hl_fortran_1_10_11-gnu-mvapich2-hpc-debuginfo~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_cpp-gnu-hpc", rpm:"libhdf5_hl_cpp-gnu-hpc~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_cpp_1_10_11-gnu-mpich-hpc-debuginfo", rpm:"libhdf5_hl_cpp_1_10_11-gnu-mpich-hpc-debuginfo~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-mpich-hpc-devel-static", rpm:"hdf5_1_10_11-gnu-mpich-hpc-devel-static~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-openmpi4-hpc-devel-static", rpm:"hdf5_1_10_11-gnu-openmpi4-hpc-devel-static~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_1_10_11-gnu-openmpi3-hpc", rpm:"libhdf5_1_10_11-gnu-openmpi3-hpc~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-openmpi3-hpc", rpm:"hdf5_1_10_11-gnu-openmpi3-hpc~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_1_10_11-gnu-mpich-hpc-debuginfo", rpm:"libhdf5_1_10_11-gnu-mpich-hpc-debuginfo~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5hl_fortran_1_10_11-gnu-openmpi4-hpc-debuginfo", rpm:"libhdf5hl_fortran_1_10_11-gnu-openmpi4-hpc-debuginfo~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_1_10_11-gnu-openmpi3-hpc", rpm:"libhdf5_hl_1_10_11-gnu-openmpi3-hpc~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_cpp-gnu-openmpi4-hpc", rpm:"libhdf5_cpp-gnu-openmpi4-hpc~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_fortran_1_10_11-gnu-openmpi4-hpc-debuginfo", rpm:"libhdf5_fortran_1_10_11-gnu-openmpi4-hpc-debuginfo~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_cpp_1_10_11-gnu-hpc-debuginfo", rpm:"libhdf5_hl_cpp_1_10_11-gnu-hpc-debuginfo~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_cpp_1_10_11-gnu-hpc-debuginfo", rpm:"libhdf5_cpp_1_10_11-gnu-hpc-debuginfo~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_1_10_11-gnu-mvapich2-hpc", rpm:"libhdf5_hl_1_10_11-gnu-mvapich2-hpc~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-mvapich2-hpc-devel", rpm:"hdf5_1_10_11-gnu-mvapich2-hpc-devel~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_fortran_1_10_11-gnu-openmpi3-hpc", rpm:"libhdf5_fortran_1_10_11-gnu-openmpi3-hpc~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_cpp-gnu-openmpi4-hpc", rpm:"libhdf5_hl_cpp-gnu-openmpi4-hpc~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_cpp_1_10_11-gnu-openmpi4-hpc", rpm:"libhdf5_hl_cpp_1_10_11-gnu-openmpi4-hpc~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl-gnu-hpc", rpm:"libhdf5_hl-gnu-hpc~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_fortran-gnu-mvapich2-hpc", rpm:"libhdf5_hl_fortran-gnu-mvapich2-hpc~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_1_10_11-gnu-openmpi4-hpc", rpm:"libhdf5_hl_1_10_11-gnu-openmpi4-hpc~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_cpp-gnu-openmpi3-hpc", rpm:"libhdf5_cpp-gnu-openmpi3-hpc~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_1_10_11-gnu-hpc", rpm:"libhdf5_1_10_11-gnu-hpc~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_fortran-gnu-openmpi4-hpc", rpm:"libhdf5_hl_fortran-gnu-openmpi4-hpc~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5hl_fortran_1_10_11-gnu-hpc", rpm:"libhdf5hl_fortran_1_10_11-gnu-hpc~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_1_10_11-gnu-mvapich2-hpc-debuginfo", rpm:"libhdf5_1_10_11-gnu-mvapich2-hpc-debuginfo~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_cpp_1_10_11-gnu-mvapich2-hpc", rpm:"libhdf5_hl_cpp_1_10_11-gnu-mvapich2-hpc~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_fortran-gnu-mvapich2-hpc", rpm:"libhdf5_fortran-gnu-mvapich2-hpc~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_1_10_11-gnu-openmpi4-hpc-debuginfo", rpm:"libhdf5_1_10_11-gnu-openmpi4-hpc-debuginfo~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-hpc-debuginfo", rpm:"hdf5_1_10_11-gnu-hpc-debuginfo~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-mpich-hpc-module", rpm:"hdf5_1_10_11-gnu-mpich-hpc-module~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-mvapich2-hpc-debugsource", rpm:"hdf5_1_10_11-gnu-mvapich2-hpc-debugsource~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_cpp_1_10_11-gnu-openmpi4-hpc", rpm:"libhdf5_cpp_1_10_11-gnu-openmpi4-hpc~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_cpp_1_10_11-gnu-mpich-hpc-debuginfo", rpm:"libhdf5_cpp_1_10_11-gnu-mpich-hpc-debuginfo~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5-gnu-mpich-hpc", rpm:"libhdf5-gnu-mpich-hpc~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl-gnu-mvapich2-hpc", rpm:"libhdf5_hl-gnu-mvapich2-hpc~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_cpp_1_10_11-gnu-openmpi3-hpc-debuginfo", rpm:"libhdf5_cpp_1_10_11-gnu-openmpi3-hpc-debuginfo~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_cpp_1_10_11-gnu-mpich-hpc", rpm:"libhdf5_cpp_1_10_11-gnu-mpich-hpc~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl-gnu-openmpi3-hpc", rpm:"libhdf5_hl-gnu-openmpi3-hpc~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5-gnu-openmpi4-hpc", rpm:"libhdf5-gnu-openmpi4-hpc~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_cpp-gnu-mvapich2-hpc", rpm:"libhdf5_cpp-gnu-mvapich2-hpc~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_fortran_1_10_11-gnu-mpich-hpc", rpm:"libhdf5_fortran_1_10_11-gnu-mpich-hpc~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5hl_fortran_1_10_11-gnu-openmpi3-hpc", rpm:"libhdf5hl_fortran_1_10_11-gnu-openmpi3-hpc~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_cpp_1_10_11-gnu-hpc", rpm:"libhdf5_cpp_1_10_11-gnu-hpc~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_fortran_1_10_11-gnu-mvapich2-hpc", rpm:"libhdf5_fortran_1_10_11-gnu-mvapich2-hpc~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5-gnu-hpc", rpm:"libhdf5-gnu-hpc~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_1_10_11-gnu-openmpi4-hpc", rpm:"libhdf5_1_10_11-gnu-openmpi4-hpc~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5-gnu-openmpi3-hpc", rpm:"libhdf5-gnu-openmpi3-hpc~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5hl_fortran_1_10_11-gnu-openmpi3-hpc-debuginfo", rpm:"libhdf5hl_fortran_1_10_11-gnu-openmpi3-hpc-debuginfo~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-hpc-debugsource", rpm:"hdf5_1_10_11-gnu-hpc-debugsource~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5hl_fortran_1_10_11-gnu-mvapich2-hpc", rpm:"libhdf5hl_fortran_1_10_11-gnu-mvapich2-hpc~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_cpp_1_10_11-gnu-openmpi3-hpc-debuginfo", rpm:"libhdf5_hl_cpp_1_10_11-gnu-openmpi3-hpc-debuginfo~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_fortran-gnu-openmpi3-hpc", rpm:"libhdf5_fortran-gnu-openmpi3-hpc~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-openmpi4-hpc", rpm:"hdf5_1_10_11-gnu-openmpi4-hpc~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_fortran-gnu-mpich-hpc", rpm:"libhdf5_hl_fortran-gnu-mpich-hpc~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl-gnu-openmpi4-hpc", rpm:"libhdf5_hl-gnu-openmpi4-hpc~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_cpp_1_10_11-gnu-openmpi4-hpc-debuginfo", rpm:"libhdf5_hl_cpp_1_10_11-gnu-openmpi4-hpc-debuginfo~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_cpp_1_10_11-gnu-mvapich2-hpc", rpm:"libhdf5_cpp_1_10_11-gnu-mvapich2-hpc~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-mpich-hpc-debugsource", rpm:"hdf5_1_10_11-gnu-mpich-hpc-debugsource~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_fortran_1_10_11-gnu-mvapich2-hpc-debuginfo", rpm:"libhdf5_fortran_1_10_11-gnu-mvapich2-hpc-debuginfo~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_cpp-gnu-hpc", rpm:"libhdf5_cpp-gnu-hpc~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_fortran-gnu-openmpi4-hpc", rpm:"libhdf5_fortran-gnu-openmpi4-hpc~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_1_10_11-gnu-openmpi3-hpc-debuginfo", rpm:"libhdf5_1_10_11-gnu-openmpi3-hpc-debuginfo~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-openmpi3-hpc-debugsource", rpm:"hdf5_1_10_11-gnu-openmpi3-hpc-debugsource~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_cpp_1_10_11-gnu-mvapich2-hpc-debuginfo", rpm:"libhdf5_cpp_1_10_11-gnu-mvapich2-hpc-debuginfo~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_1_10_11-gnu-openmpi4-hpc-debuginfo", rpm:"libhdf5_hl_1_10_11-gnu-openmpi4-hpc-debuginfo~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_cpp-gnu-openmpi3-hpc", rpm:"libhdf5_hl_cpp-gnu-openmpi3-hpc~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_1_10_11-gnu-mpich-hpc", rpm:"libhdf5_hl_1_10_11-gnu-mpich-hpc~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-hpc", rpm:"hdf5_1_10_11-gnu-hpc~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-hpc-examples", rpm:"hdf5_1_10_11-hpc-examples~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-mvapich2-hpc-module", rpm:"hdf5_1_10_11-gnu-mvapich2-hpc-module~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-mpich-hpc-debuginfo", rpm:"hdf5_1_10_11-gnu-mpich-hpc-debuginfo~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_cpp_1_10_11-gnu-openmpi3-hpc", rpm:"libhdf5_hl_cpp_1_10_11-gnu-openmpi3-hpc~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_cpp-gnu-mpich-hpc", rpm:"libhdf5_hl_cpp-gnu-mpich-hpc~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-openmpi4-hpc-devel", rpm:"hdf5_1_10_11-gnu-openmpi4-hpc-devel~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_cpp-gnu-mvapich2-hpc", rpm:"libhdf5_hl_cpp-gnu-mvapich2-hpc~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-mvapich2-hpc-devel-static", rpm:"hdf5_1_10_11-gnu-mvapich2-hpc-devel-static~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_1_10_11-gnu-mpich-hpc-debuginfo", rpm:"libhdf5_hl_1_10_11-gnu-mpich-hpc-debuginfo~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_cpp_1_10_11-gnu-mpich-hpc", rpm:"libhdf5_hl_cpp_1_10_11-gnu-mpich-hpc~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_fortran-gnu-hpc", rpm:"libhdf5_fortran-gnu-hpc~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5hl_fortran_1_10_11-gnu-mpich-hpc-debuginfo", rpm:"libhdf5hl_fortran_1_10_11-gnu-mpich-hpc-debuginfo~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-openmpi3-hpc-devel", rpm:"hdf5_1_10_11-gnu-openmpi3-hpc-devel~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-hpc-devel-static", rpm:"hdf5_1_10_11-gnu-hpc-devel-static~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_fortran-gnu-mpich-hpc", rpm:"libhdf5_fortran-gnu-mpich-hpc~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5-gnu-mvapich2-hpc", rpm:"libhdf5-gnu-mvapich2-hpc~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_1_10_11-gnu-hpc-debuginfo", rpm:"libhdf5_1_10_11-gnu-hpc-debuginfo~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-mpich-hpc-devel", rpm:"hdf5_1_10_11-gnu-mpich-hpc-devel~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_fortran_1_10_11-gnu-openmpi4-hpc", rpm:"libhdf5_fortran_1_10_11-gnu-openmpi4-hpc~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_cpp_1_10_11-gnu-hpc", rpm:"libhdf5_hl_cpp_1_10_11-gnu-hpc~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-mpich-hpc", rpm:"hdf5_1_10_11-gnu-mpich-hpc~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_fortran-gnu-hpc", rpm:"libhdf5_hl_fortran-gnu-hpc~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_cpp_1_10_11-gnu-openmpi4-hpc-debuginfo", rpm:"libhdf5_cpp_1_10_11-gnu-openmpi4-hpc-debuginfo~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-openmpi3-hpc-debuginfo", rpm:"hdf5_1_10_11-gnu-openmpi3-hpc-debuginfo~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5hl_fortran_1_10_11-gnu-hpc-debuginfo", rpm:"libhdf5hl_fortran_1_10_11-gnu-hpc-debuginfo~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-mvapich2-hpc-debuginfo", rpm:"hdf5_1_10_11-gnu-mvapich2-hpc-debuginfo~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_cpp_1_10_11-gnu-mvapich2-hpc-debuginfo", rpm:"libhdf5_hl_cpp_1_10_11-gnu-mvapich2-hpc-debuginfo~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_1_10_11-gnu-mpich-hpc", rpm:"libhdf5_1_10_11-gnu-mpich-hpc~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5hl_fortran_1_10_11-gnu-openmpi4-hpc", rpm:"libhdf5hl_fortran_1_10_11-gnu-openmpi4-hpc~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_fortran_1_10_11-gnu-hpc", rpm:"libhdf5_fortran_1_10_11-gnu-hpc~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl-gnu-mpich-hpc", rpm:"libhdf5_hl-gnu-mpich-hpc~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-hpc-module", rpm:"hdf5_1_10_11-gnu-hpc-module~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_1_10_11-gnu-hpc", rpm:"libhdf5_hl_1_10_11-gnu-hpc~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_fortran-gnu-openmpi3-hpc", rpm:"libhdf5_hl_fortran-gnu-openmpi3-hpc~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5hl_fortran_1_10_11-gnu-mpich-hpc", rpm:"libhdf5hl_fortran_1_10_11-gnu-mpich-hpc~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-hpc-devel", rpm:"hdf5_1_10_11-gnu-hpc-devel~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_cpp_1_10_11-gnu-openmpi3-hpc", rpm:"libhdf5_cpp_1_10_11-gnu-openmpi3-hpc~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_fortran_1_10_11-gnu-hpc-debuginfo", rpm:"libhdf5_fortran_1_10_11-gnu-hpc-debuginfo~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_1_10_11-gnu-hpc-debuginfo", rpm:"libhdf5_hl_1_10_11-gnu-hpc-debuginfo~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_cpp-gnu-mpich-hpc", rpm:"libhdf5_cpp-gnu-mpich-hpc~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-openmpi4-hpc-module", rpm:"hdf5_1_10_11-gnu-openmpi4-hpc-module~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-openmpi3-hpc-module", rpm:"hdf5_1_10_11-gnu-openmpi3-hpc-module~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_1_10_11-gnu-openmpi3-hpc-debuginfo", rpm:"libhdf5_hl_1_10_11-gnu-openmpi3-hpc-debuginfo~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_1_10_11-gnu-mvapich2-hpc-debuginfo", rpm:"libhdf5_hl_1_10_11-gnu-mvapich2-hpc-debuginfo~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_fortran_1_10_11-gnu-openmpi3-hpc-debuginfo", rpm:"libhdf5_fortran_1_10_11-gnu-openmpi3-hpc-debuginfo~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-openmpi3-hpc-devel-static", rpm:"hdf5_1_10_11-gnu-openmpi3-hpc-devel-static~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_fortran_1_10_11-gnu-mpich-hpc-debuginfo", rpm:"libhdf5_fortran_1_10_11-gnu-mpich-hpc-debuginfo~1.10.11~150300.4.16.15", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtrilinos-gnu-openmpi2-hpc", rpm:"libtrilinos-gnu-openmpi2-hpc~13.2.0~150300.3.12.9", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtrilinos_13_2_0-gnu-openmpi3-hpc-debuginfo", rpm:"libtrilinos_13_2_0-gnu-openmpi3-hpc-debuginfo~13.2.0~150300.3.12.16", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtrilinos_13_2_0-gnu-mpich-hpc-debuginfo", rpm:"libtrilinos_13_2_0-gnu-mpich-hpc-debuginfo~13.2.0~150300.3.12.18", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtrilinos_13_2_0-gnu-mpich-hpc", rpm:"libtrilinos_13_2_0-gnu-mpich-hpc~13.2.0~150300.3.12.18", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"trilinos_13_2_0-gnu-mpich-hpc-devel", rpm:"trilinos_13_2_0-gnu-mpich-hpc-devel~13.2.0~150300.3.12.18", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"trilinos_13_2_0-gnu-mvapich2-hpc-debugsource", rpm:"trilinos_13_2_0-gnu-mvapich2-hpc-debugsource~13.2.0~150300.3.12.18", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtrilinos_13_2_0-gnu-openmpi4-hpc", rpm:"libtrilinos_13_2_0-gnu-openmpi4-hpc~13.2.0~150300.3.12.18", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"trilinos_13_2_0-gnu-openmpi3-hpc-debugsource", rpm:"trilinos_13_2_0-gnu-openmpi3-hpc-debugsource~13.2.0~150300.3.12.16", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtrilinos_13_2_0-gnu-openmpi2-hpc-debuginfo", rpm:"libtrilinos_13_2_0-gnu-openmpi2-hpc-debuginfo~13.2.0~150300.3.12.9", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtrilinos_13_2_0-gnu-openmpi3-hpc", rpm:"libtrilinos_13_2_0-gnu-openmpi3-hpc~13.2.0~150300.3.12.16", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtrilinos_13_2_0-gnu-openmpi2-hpc", rpm:"libtrilinos_13_2_0-gnu-openmpi2-hpc~13.2.0~150300.3.12.9", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtrilinos_13_2_0-gnu-mvapich2-hpc", rpm:"libtrilinos_13_2_0-gnu-mvapich2-hpc~13.2.0~150300.3.12.18", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"trilinos_13_2_0-gnu-mvapich2-hpc-devel", rpm:"trilinos_13_2_0-gnu-mvapich2-hpc-devel~13.2.0~150300.3.12.18", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtrilinos-gnu-mvapich2-hpc", rpm:"libtrilinos-gnu-mvapich2-hpc~13.2.0~150300.3.12.18", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"trilinos_13_2_0-gnu-mpich-hpc-debugsource", rpm:"trilinos_13_2_0-gnu-mpich-hpc-debugsource~13.2.0~150300.3.12.18", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"trilinos_13_2_0-gnu-openmpi2-hpc-debugsource", rpm:"trilinos_13_2_0-gnu-openmpi2-hpc-debugsource~13.2.0~150300.3.12.9", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtrilinos_13_2_0-gnu-openmpi4-hpc-debuginfo", rpm:"libtrilinos_13_2_0-gnu-openmpi4-hpc-debuginfo~13.2.0~150300.3.12.18", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtrilinos_13_2_0-gnu-mvapich2-hpc-debuginfo", rpm:"libtrilinos_13_2_0-gnu-mvapich2-hpc-debuginfo~13.2.0~150300.3.12.18", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtrilinos-gnu-openmpi4-hpc", rpm:"libtrilinos-gnu-openmpi4-hpc~13.2.0~150300.3.12.18", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtrilinos-gnu-openmpi3-hpc", rpm:"libtrilinos-gnu-openmpi3-hpc~13.2.0~150300.3.12.16", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"trilinos_13_2_0-gnu-openmpi4-hpc-debugsource", rpm:"trilinos_13_2_0-gnu-openmpi4-hpc-debugsource~13.2.0~150300.3.12.18", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtrilinos-gnu-mpich-hpc", rpm:"libtrilinos-gnu-mpich-hpc~13.2.0~150300.3.12.18", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"trilinos_13_2_0-gnu-openmpi2-hpc-devel", rpm:"trilinos_13_2_0-gnu-openmpi2-hpc-devel~13.2.0~150300.3.12.9", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"trilinos_13_2_0-gnu-openmpi3-hpc-devel", rpm:"trilinos_13_2_0-gnu-openmpi3-hpc-devel~13.2.0~150300.3.12.16", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"trilinos_13_2_0-gnu-openmpi4-hpc-devel", rpm:"trilinos_13_2_0-gnu-openmpi4-hpc-devel~13.2.0~150300.3.12.18", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"trilinos_13_2_0-hpc-debugsource", rpm:"trilinos_13_2_0-hpc-debugsource~13.2.0~150300.3.12.9", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf18-64bit", rpm:"libnetcdf18-64bit~4.7.4~150300.4.7.9", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf18-openmpi2-64bit", rpm:"libnetcdf18-openmpi2-64bit~4.7.4~150300.4.7.9", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf18-openmpi2-64bit-debuginfo", rpm:"libnetcdf18-openmpi2-64bit-debuginfo~4.7.4~150300.4.7.9", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf18-64bit-debuginfo", rpm:"libnetcdf18-64bit-debuginfo~4.7.4~150300.4.7.9", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf18-openmpi4-64bit-debuginfo", rpm:"libnetcdf18-openmpi4-64bit-debuginfo~4.7.4~150300.4.7.9", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf18-openmpi3-64bit-debuginfo", rpm:"libnetcdf18-openmpi3-64bit-debuginfo~4.7.4~150300.4.7.9", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf18-openmpi3-64bit", rpm:"libnetcdf18-openmpi3-64bit~4.7.4~150300.4.7.9", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf18-openmpi4-64bit", rpm:"libnetcdf18-openmpi4-64bit~4.7.4~150300.4.7.9", rls:"openSUSELeap15.3"))) {
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