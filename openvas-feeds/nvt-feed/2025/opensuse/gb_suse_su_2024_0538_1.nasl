# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2024.0538.1");
  script_cve_id("CVE-2016-4332", "CVE-2018-11202", "CVE-2019-8396", "CVE-2020-10812", "CVE-2021-37501");
  script_tag(name:"creation_date", value:"2025-02-25 14:26:30 +0000 (Tue, 25 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-11-22 02:05:42 +0000 (Tue, 22 Nov 2016)");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:0538-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0538-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20240538-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1011205");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1093641");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1125882");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1167400");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207973");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-February/017975.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'hdf5' package(s) announced via the SUSE-SU-2024:0538-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for hdf5 fixes the following issues:

Updated to version 1.10.11

 * Changed the error handling for a not found path in the find
 plugin process.
 * Fixed CVE-2018-11202, a malformed file could result in chunk
 index memory leaks.
 * Fixed a file space allocation bug in the parallel library for
 chunked datasets.
 * Fixed an assertion failure in Parallel HDF5 when a file can't
 be created due to an invalid library version bounds setting.
 * Fixed an assertion in a previous fix for CVE-2016-4332.
 * Fixed segfault on file close in h5debug which fails with a core
 dump on a file that has an illegal file size in its cache image.
 Fixes HDFFV-11052, CVE-2020-10812.
 * Fixed memory leaks that could occur when reading a dataset from
 a malformed file.
 * Fixed a bug in H5Ocopy that could generate invalid HDF5 files
 * Fixed potential heap buffer overflow in decoding of link info
 message.
 * Fixed potential buffer overrun issues in some object header
 decode routines.
 * Fixed a heap buffer overflow that occurs when reading from
 a dataset with a compact layout within a malformed HDF5 file.
 * Fixed CVE-2019-8396, malformed HDF5 files where content does
 not match expected size.
 * Fixed memory leak when running h5dump with proof of
 vulnerability file.
 * Added option --no-compact-subset to h5diff.

Fixes since 1.10.10:

 * Fixed a memory corruption when reading from dataset using a
 hyperslab selection in file dataspace and a point selection
 memory dataspace.
 * Fix CVE-2021-37501
 * Fixed an issue with variable length attributes.
 * Fixed an issue with hyperslab selections where an incorrect
 combined selection was produced.
 * Fixed an issue with attribute type conversion with compound
 datatypes.
 * Modified H5Fstart_swmr_write() to preserve DAPL properties.
 * Converted an assertion on (possibly corrupt) file contents to
 a normal error check.
 * Fixed memory leak with variable-length fill value in
 H5O_fill_convert().
 * Fix h5repack to only print output when verbose option is
 selected.

Fixes since 1.10.9:

 * Several improvements to parallel compression feature,
 including:
 + Improved support for collective I/O (for both writes and
 reads).
 + Reduction of copying of application data buffers passed to
 H5Dwrite.
 + Addition of support for incremental file space allocation
 for filtered datasets created in parallel.
 + Addition of support for HDF5's 'don't filter partial edge
 chunks' flag
 + Addition of proper support for HDF5 fill values with the
 feature.
 + Addition of 'H5_HAVE_PARALLEL_FILTERED_WRITES' macro to
 H5pubconf.h
 so HDF5 applications can determine at compile-time whether
 the feature is available.
 + Addition of simple examples
 * h5repack added an optional verbose value for reporting R/W
 timing.
 * Fixed a metadata cache bug when resizing a pinned/protected
 cache entry.
 * Fixed a problem with the H5_VERS_RELEASE check in the
 ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'hdf5' package(s) on openSUSE Leap 15.5.");

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

  if(!isnull(res = isrpmvuln(pkg:"hdf5-gnu-hpc", rpm:"hdf5-gnu-hpc~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5-gnu-hpc-devel", rpm:"hdf5-gnu-hpc-devel~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5-gnu-mpich-hpc", rpm:"hdf5-gnu-mpich-hpc~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5-gnu-mpich-hpc-devel", rpm:"hdf5-gnu-mpich-hpc-devel~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5-gnu-mvapich2-hpc", rpm:"hdf5-gnu-mvapich2-hpc~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5-gnu-mvapich2-hpc-devel", rpm:"hdf5-gnu-mvapich2-hpc-devel~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5-gnu-openmpi3-hpc", rpm:"hdf5-gnu-openmpi3-hpc~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5-gnu-openmpi3-hpc-devel", rpm:"hdf5-gnu-openmpi3-hpc-devel~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5-gnu-openmpi4-hpc", rpm:"hdf5-gnu-openmpi4-hpc~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5-gnu-openmpi4-hpc-devel", rpm:"hdf5-gnu-openmpi4-hpc-devel~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5-hpc-examples", rpm:"hdf5-hpc-examples~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-hpc", rpm:"hdf5_1_10_11-gnu-hpc~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-hpc-devel", rpm:"hdf5_1_10_11-gnu-hpc-devel~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-hpc-devel-static", rpm:"hdf5_1_10_11-gnu-hpc-devel-static~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-hpc-module", rpm:"hdf5_1_10_11-gnu-hpc-module~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-mpich-hpc", rpm:"hdf5_1_10_11-gnu-mpich-hpc~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-mpich-hpc-devel", rpm:"hdf5_1_10_11-gnu-mpich-hpc-devel~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-mpich-hpc-devel-static", rpm:"hdf5_1_10_11-gnu-mpich-hpc-devel-static~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-mpich-hpc-module", rpm:"hdf5_1_10_11-gnu-mpich-hpc-module~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-mvapich2-hpc", rpm:"hdf5_1_10_11-gnu-mvapich2-hpc~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-mvapich2-hpc-devel", rpm:"hdf5_1_10_11-gnu-mvapich2-hpc-devel~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-mvapich2-hpc-devel-static", rpm:"hdf5_1_10_11-gnu-mvapich2-hpc-devel-static~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-mvapich2-hpc-module", rpm:"hdf5_1_10_11-gnu-mvapich2-hpc-module~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-openmpi3-hpc", rpm:"hdf5_1_10_11-gnu-openmpi3-hpc~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-openmpi3-hpc-devel", rpm:"hdf5_1_10_11-gnu-openmpi3-hpc-devel~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-openmpi3-hpc-devel-static", rpm:"hdf5_1_10_11-gnu-openmpi3-hpc-devel-static~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-openmpi3-hpc-module", rpm:"hdf5_1_10_11-gnu-openmpi3-hpc-module~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-openmpi4-hpc", rpm:"hdf5_1_10_11-gnu-openmpi4-hpc~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-openmpi4-hpc-devel", rpm:"hdf5_1_10_11-gnu-openmpi4-hpc-devel~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-openmpi4-hpc-devel-static", rpm:"hdf5_1_10_11-gnu-openmpi4-hpc-devel-static~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-gnu-openmpi4-hpc-module", rpm:"hdf5_1_10_11-gnu-openmpi4-hpc-module~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_11-hpc-examples", rpm:"hdf5_1_10_11-hpc-examples~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5-gnu-hpc", rpm:"libhdf5-gnu-hpc~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5-gnu-mpich-hpc", rpm:"libhdf5-gnu-mpich-hpc~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5-gnu-mvapich2-hpc", rpm:"libhdf5-gnu-mvapich2-hpc~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5-gnu-openmpi3-hpc", rpm:"libhdf5-gnu-openmpi3-hpc~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5-gnu-openmpi4-hpc", rpm:"libhdf5-gnu-openmpi4-hpc~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_1_10_11-gnu-hpc", rpm:"libhdf5_1_10_11-gnu-hpc~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_1_10_11-gnu-mpich-hpc", rpm:"libhdf5_1_10_11-gnu-mpich-hpc~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_1_10_11-gnu-mvapich2-hpc", rpm:"libhdf5_1_10_11-gnu-mvapich2-hpc~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_1_10_11-gnu-openmpi3-hpc", rpm:"libhdf5_1_10_11-gnu-openmpi3-hpc~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_1_10_11-gnu-openmpi4-hpc", rpm:"libhdf5_1_10_11-gnu-openmpi4-hpc~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_cpp-gnu-hpc", rpm:"libhdf5_cpp-gnu-hpc~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_cpp-gnu-mpich-hpc", rpm:"libhdf5_cpp-gnu-mpich-hpc~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_cpp-gnu-mvapich2-hpc", rpm:"libhdf5_cpp-gnu-mvapich2-hpc~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_cpp-gnu-openmpi3-hpc", rpm:"libhdf5_cpp-gnu-openmpi3-hpc~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_cpp-gnu-openmpi4-hpc", rpm:"libhdf5_cpp-gnu-openmpi4-hpc~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_cpp_1_10_11-gnu-hpc", rpm:"libhdf5_cpp_1_10_11-gnu-hpc~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_cpp_1_10_11-gnu-mpich-hpc", rpm:"libhdf5_cpp_1_10_11-gnu-mpich-hpc~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_cpp_1_10_11-gnu-mvapich2-hpc", rpm:"libhdf5_cpp_1_10_11-gnu-mvapich2-hpc~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_cpp_1_10_11-gnu-openmpi3-hpc", rpm:"libhdf5_cpp_1_10_11-gnu-openmpi3-hpc~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_cpp_1_10_11-gnu-openmpi4-hpc", rpm:"libhdf5_cpp_1_10_11-gnu-openmpi4-hpc~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_fortran-gnu-hpc", rpm:"libhdf5_fortran-gnu-hpc~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_fortran-gnu-mpich-hpc", rpm:"libhdf5_fortran-gnu-mpich-hpc~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_fortran-gnu-mvapich2-hpc", rpm:"libhdf5_fortran-gnu-mvapich2-hpc~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_fortran-gnu-openmpi3-hpc", rpm:"libhdf5_fortran-gnu-openmpi3-hpc~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_fortran-gnu-openmpi4-hpc", rpm:"libhdf5_fortran-gnu-openmpi4-hpc~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_fortran_1_10_11-gnu-hpc", rpm:"libhdf5_fortran_1_10_11-gnu-hpc~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_fortran_1_10_11-gnu-mpich-hpc", rpm:"libhdf5_fortran_1_10_11-gnu-mpich-hpc~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_fortran_1_10_11-gnu-mvapich2-hpc", rpm:"libhdf5_fortran_1_10_11-gnu-mvapich2-hpc~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_fortran_1_10_11-gnu-openmpi3-hpc", rpm:"libhdf5_fortran_1_10_11-gnu-openmpi3-hpc~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_fortran_1_10_11-gnu-openmpi4-hpc", rpm:"libhdf5_fortran_1_10_11-gnu-openmpi4-hpc~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl-gnu-hpc", rpm:"libhdf5_hl-gnu-hpc~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl-gnu-mpich-hpc", rpm:"libhdf5_hl-gnu-mpich-hpc~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl-gnu-mvapich2-hpc", rpm:"libhdf5_hl-gnu-mvapich2-hpc~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl-gnu-openmpi3-hpc", rpm:"libhdf5_hl-gnu-openmpi3-hpc~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl-gnu-openmpi4-hpc", rpm:"libhdf5_hl-gnu-openmpi4-hpc~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_1_10_11-gnu-hpc", rpm:"libhdf5_hl_1_10_11-gnu-hpc~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_1_10_11-gnu-mpich-hpc", rpm:"libhdf5_hl_1_10_11-gnu-mpich-hpc~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_1_10_11-gnu-mvapich2-hpc", rpm:"libhdf5_hl_1_10_11-gnu-mvapich2-hpc~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_1_10_11-gnu-openmpi3-hpc", rpm:"libhdf5_hl_1_10_11-gnu-openmpi3-hpc~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_1_10_11-gnu-openmpi4-hpc", rpm:"libhdf5_hl_1_10_11-gnu-openmpi4-hpc~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_cpp-gnu-hpc", rpm:"libhdf5_hl_cpp-gnu-hpc~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_cpp-gnu-mpich-hpc", rpm:"libhdf5_hl_cpp-gnu-mpich-hpc~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_cpp-gnu-mvapich2-hpc", rpm:"libhdf5_hl_cpp-gnu-mvapich2-hpc~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_cpp-gnu-openmpi3-hpc", rpm:"libhdf5_hl_cpp-gnu-openmpi3-hpc~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_cpp-gnu-openmpi4-hpc", rpm:"libhdf5_hl_cpp-gnu-openmpi4-hpc~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_cpp_1_10_11-gnu-hpc", rpm:"libhdf5_hl_cpp_1_10_11-gnu-hpc~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_cpp_1_10_11-gnu-mpich-hpc", rpm:"libhdf5_hl_cpp_1_10_11-gnu-mpich-hpc~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_cpp_1_10_11-gnu-mvapich2-hpc", rpm:"libhdf5_hl_cpp_1_10_11-gnu-mvapich2-hpc~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_cpp_1_10_11-gnu-openmpi3-hpc", rpm:"libhdf5_hl_cpp_1_10_11-gnu-openmpi3-hpc~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_cpp_1_10_11-gnu-openmpi4-hpc", rpm:"libhdf5_hl_cpp_1_10_11-gnu-openmpi4-hpc~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_fortran-gnu-hpc", rpm:"libhdf5_hl_fortran-gnu-hpc~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_fortran-gnu-mpich-hpc", rpm:"libhdf5_hl_fortran-gnu-mpich-hpc~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_fortran-gnu-mvapich2-hpc", rpm:"libhdf5_hl_fortran-gnu-mvapich2-hpc~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_fortran-gnu-openmpi3-hpc", rpm:"libhdf5_hl_fortran-gnu-openmpi3-hpc~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_fortran-gnu-openmpi4-hpc", rpm:"libhdf5_hl_fortran-gnu-openmpi4-hpc~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5hl_fortran_1_10_11-gnu-hpc", rpm:"libhdf5hl_fortran_1_10_11-gnu-hpc~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5hl_fortran_1_10_11-gnu-mpich-hpc", rpm:"libhdf5hl_fortran_1_10_11-gnu-mpich-hpc~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5hl_fortran_1_10_11-gnu-mvapich2-hpc", rpm:"libhdf5hl_fortran_1_10_11-gnu-mvapich2-hpc~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5hl_fortran_1_10_11-gnu-openmpi3-hpc", rpm:"libhdf5hl_fortran_1_10_11-gnu-openmpi3-hpc~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5hl_fortran_1_10_11-gnu-openmpi4-hpc", rpm:"libhdf5hl_fortran_1_10_11-gnu-openmpi4-hpc~1.10.11~150400.3.12.1", rls:"openSUSELeap15.5"))) {
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
