# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833188");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-4039");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-14 20:01:22 +0000 (Thu, 14 Sep 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:46:26 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for gcc13 (SUSE-SU-2023:4162-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.5|openSUSELeapMicro5\.3|openSUSELeapMicro5\.4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:4162-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/YOFUKXJH42YHQ7HQMK3LB2WRG3BATX3G");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gcc13'
  package(s) announced via the SUSE-SU-2023:4162-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for gcc13 fixes the following issues:

  This update ship the GCC 13.2 compiler suite and its base libraries.

  The compiler base libraries are provided for all SUSE Linux Enterprise 15
  versions and replace the same named GCC 12 ones.

  The new compilers for C, C++, and Fortran are provided for SUSE Linux Enterprise
  15 SP4 and SP5, and provided in the 'Development Tools' module.

  The Go, D, Ada and Modula 2 language compiler parts are available unsupported
  via the PackageHub repositories.

  To use gcc13 compilers use:

  * install 'gcc13' or 'gcc13-c++' or one of the other 'gcc13-COMPILER' frontend
      packages.

  * override your Makefile to use CC=gcc13, CXX=g++13 and similar overrides for
      the other languages.

  Detailed changes:

  * CVE-2023-4039: Fixed -fstack-protector issues on aarch64 with variable
      length stack allocations. (bsc#1214052)

  * Turn cross compiler to s390x to a glibc cross. [bsc#1214460]

  * Also handle -static-pie in the default-PIE specs

  * Fixed missed optimization in Skia resulting in Firefox crashes when building
      with LTO. [bsc#1212101]

  * Make libstdc++6-devel packages own their directories since they can be
      installed standalone. [bsc#1211427]

  * Add new x86-related intrinsics (amxcomplexintrin.h).

  * RISC-V: Add support for inlining subword atomic operations

  * Use --enable-link-serialization rather that --enable-link-mutex, the benefit
      of the former one is that the linker jobs are not holding tokens of the
      make's jobserver.
      general state of BPF with GCC.

  * Add bootstrap conditional to allow --without=bootstrap to be specified to
      speed up local builds for testing.

  * Bump included newlib to version 4.3.0.

  * Also package libhwasan_preinit.o on aarch64.

  * Configure external timezone database provided by the timezone package. Make
      libstdc++6 recommend timezone to get a fully working std::chrono. Install
      timezone when running the testsuite.

  * Package libhwasan_preinit.o on x86_64.

  * Fixed unwinding on aarch64 with pointer signing. [bsc#1206684]

  * Enable PRU flavour for gcc13

  * update floatn fixinclude pickup to check each header separately
      (bsc#1206480)

  * Redo floatn fixinclude pick-up to simply keep what is there.

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'gcc13' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5, openSUSE Leap Micro 5.3, openSUSE Leap Micro 5.4.");

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

  if(!isnull(res = isrpmvuln(pkg:"libgo22-debuginfo", rpm:"libgo22-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc13-debugsource", rpm:"gcc13-debugsource~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-debuginfo", rpm:"libstdc++6-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libobjc4-debuginfo", rpm:"libobjc4-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-pp", rpm:"libstdc++6-pp~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libubsan1", rpm:"libubsan1~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc13-ada-debuginfo", rpm:"gcc13-ada-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc13-go", rpm:"gcc13-go~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc13-obj-c++", rpm:"gcc13-obj-c++~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc13-fortran", rpm:"gcc13-fortran~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libatomic1", rpm:"libatomic1~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc13-m2", rpm:"gcc13-m2~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libada13", rpm:"libada13~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libobjc4", rpm:"libobjc4~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtsan2-debuginfo", rpm:"libtsan2-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc13-debuginfo", rpm:"gcc13-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libm2cor18-debuginfo", rpm:"libm2cor18-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libm2pim18", rpm:"libm2pim18~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgomp1", rpm:"libgomp1~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc13-fortran-debuginfo", rpm:"gcc13-fortran-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc13-PIE", rpm:"gcc13-PIE~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libm2cor18", rpm:"libm2cor18~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libatomic1-debuginfo", rpm:"libatomic1-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cpp13-debuginfo", rpm:"cpp13-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgo22", rpm:"libgo22~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgomp1-debuginfo", rpm:"libgomp1-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgfortran5", rpm:"libgfortran5~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc13-objc", rpm:"gcc13-objc~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libitm1-debuginfo", rpm:"libitm1-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc13-ada", rpm:"gcc13-ada~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libm2log18-debuginfo", rpm:"libm2log18-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-locale", rpm:"libstdc++6-locale~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libm2iso18", rpm:"libm2iso18~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblsan0-debuginfo", rpm:"liblsan0-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc13-locale", rpm:"gcc13-locale~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libubsan1-debuginfo", rpm:"libubsan1-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc13-c++-debuginfo", rpm:"gcc13-c++-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc13-m2-debuginfo", rpm:"gcc13-m2-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libm2min18-debuginfo", rpm:"libm2min18-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblsan0", rpm:"liblsan0~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-devel-gcc13", rpm:"libstdc++6-devel-gcc13~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libm2log18", rpm:"libm2log18~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc13-go-debuginfo", rpm:"gcc13-go-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libm2min18", rpm:"libm2min18~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasan8", rpm:"libasan8~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cpp13", rpm:"cpp13~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc13-objc-debuginfo", rpm:"gcc13-objc-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6", rpm:"libstdc++6~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libm2iso18-debuginfo", rpm:"libm2iso18-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc13", rpm:"gcc13~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc13-c++", rpm:"gcc13-c++~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasan8-debuginfo", rpm:"libasan8-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libm2pim18-debuginfo", rpm:"libm2pim18-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc13-obj-c++-debuginfo", rpm:"gcc13-obj-c++-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcc_s1-debuginfo", rpm:"libgcc_s1-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcc_s1", rpm:"libgcc_s1~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libitm1", rpm:"libitm1~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libada13-debuginfo", rpm:"libada13-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgfortran5-debuginfo", rpm:"libgfortran5-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtsan2", rpm:"libtsan2~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-nvptx-newlib13-devel", rpm:"cross-nvptx-newlib13-devel~13.2.1+git7813~150000.1.3.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-nvptx-gcc13", rpm:"cross-nvptx-gcc13~13.2.1+git7813~150000.1.3.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquadmath0-32bit", rpm:"libquadmath0-32bit~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-nvptx-gcc13-debugsource", rpm:"cross-nvptx-gcc13-debugsource~13.2.1+git7813~150000.1.3.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquadmath0-32bit-debuginfo", rpm:"libquadmath0-32bit-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-nvptx-gcc13-debuginfo", rpm:"cross-nvptx-gcc13-debuginfo~13.2.1+git7813~150000.1.3.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgo22-32bit", rpm:"libgo22-32bit~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libm2pim18-32bit-debuginfo", rpm:"libm2pim18-32bit-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgomp1-32bit-debuginfo", rpm:"libgomp1-32bit-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasan8-32bit", rpm:"libasan8-32bit~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgphobos4-32bit", rpm:"libgphobos4-32bit~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libitm1-32bit", rpm:"libitm1-32bit~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libm2cor18-32bit-debuginfo", rpm:"libm2cor18-32bit-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasan8-32bit-debuginfo", rpm:"libasan8-32bit-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcc_s1-32bit", rpm:"libgcc_s1-32bit~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libm2log18-32bit-debuginfo", rpm:"libm2log18-32bit-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libobjc4-32bit", rpm:"libobjc4-32bit~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc13-d-32bit", rpm:"gcc13-d-32bit~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc13-go-32bit", rpm:"gcc13-go-32bit~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libubsan1-32bit-debuginfo", rpm:"libubsan1-32bit-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libatomic1-32bit", rpm:"libatomic1-32bit~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-32bit", rpm:"libstdc++6-32bit~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-32bit-debuginfo", rpm:"libstdc++6-32bit-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc13-objc-32bit", rpm:"gcc13-objc-32bit~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc13-m2-32bit", rpm:"gcc13-m2-32bit~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgdruntime4-32bit-debuginfo", rpm:"libgdruntime4-32bit-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libm2iso18-32bit", rpm:"libm2iso18-32bit~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libobjc4-32bit-debuginfo", rpm:"libobjc4-32bit-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgdruntime4-32bit", rpm:"libgdruntime4-32bit~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc13-32bit", rpm:"gcc13-32bit~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libm2iso18-32bit-debuginfo", rpm:"libm2iso18-32bit-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libubsan1-32bit", rpm:"libubsan1-32bit~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libada13-32bit", rpm:"libada13-32bit~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc13-ada-32bit", rpm:"gcc13-ada-32bit~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libitm1-32bit-debuginfo", rpm:"libitm1-32bit-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-pp-32bit", rpm:"libstdc++6-pp-32bit~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libada13-32bit-debuginfo", rpm:"libada13-32bit-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgfortran5-32bit", rpm:"libgfortran5-32bit~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libm2min18-32bit-debuginfo", rpm:"libm2min18-32bit-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc13-obj-c++-32bit", rpm:"gcc13-obj-c++-32bit~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgomp1-32bit", rpm:"libgomp1-32bit~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libm2cor18-32bit", rpm:"libm2cor18-32bit~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcc_s1-32bit-debuginfo", rpm:"libgcc_s1-32bit-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgfortran5-32bit-debuginfo", rpm:"libgfortran5-32bit-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libm2min18-32bit", rpm:"libm2min18-32bit~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgphobos4-32bit-debuginfo", rpm:"libgphobos4-32bit-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc13-c++-32bit", rpm:"gcc13-c++-32bit~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgo22-32bit-debuginfo", rpm:"libgo22-32bit-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libm2pim18-32bit", rpm:"libm2pim18-32bit~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-devel-gcc13-32bit", rpm:"libstdc++6-devel-gcc13-32bit~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libm2log18-32bit", rpm:"libm2log18-32bit~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libatomic1-32bit-debuginfo", rpm:"libatomic1-32bit-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc13-fortran-32bit", rpm:"gcc13-fortran-32bit~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgphobos4", rpm:"libgphobos4~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc13-d-debuginfo", rpm:"gcc13-d-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgdruntime4", rpm:"libgdruntime4~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc13-d", rpm:"gcc13-d~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgdruntime4-debuginfo", rpm:"libgdruntime4-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgphobos4-debuginfo", rpm:"libgphobos4-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc13-info", rpm:"gcc13-info~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhwasan0-debuginfo", rpm:"libhwasan0-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhwasan0", rpm:"libhwasan0~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquadmath0-debuginfo", rpm:"libquadmath0-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquadmath0", rpm:"libquadmath0~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"libgo22-debuginfo", rpm:"libgo22-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc13-debugsource", rpm:"gcc13-debugsource~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-debuginfo", rpm:"libstdc++6-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libobjc4-debuginfo", rpm:"libobjc4-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-pp", rpm:"libstdc++6-pp~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libubsan1", rpm:"libubsan1~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc13-ada-debuginfo", rpm:"gcc13-ada-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc13-go", rpm:"gcc13-go~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc13-obj-c++", rpm:"gcc13-obj-c++~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc13-fortran", rpm:"gcc13-fortran~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libatomic1", rpm:"libatomic1~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc13-m2", rpm:"gcc13-m2~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libada13", rpm:"libada13~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libobjc4", rpm:"libobjc4~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtsan2-debuginfo", rpm:"libtsan2-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc13-debuginfo", rpm:"gcc13-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libm2cor18-debuginfo", rpm:"libm2cor18-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libm2pim18", rpm:"libm2pim18~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgomp1", rpm:"libgomp1~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc13-fortran-debuginfo", rpm:"gcc13-fortran-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc13-PIE", rpm:"gcc13-PIE~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libm2cor18", rpm:"libm2cor18~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libatomic1-debuginfo", rpm:"libatomic1-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cpp13-debuginfo", rpm:"cpp13-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgo22", rpm:"libgo22~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgomp1-debuginfo", rpm:"libgomp1-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgfortran5", rpm:"libgfortran5~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc13-objc", rpm:"gcc13-objc~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libitm1-debuginfo", rpm:"libitm1-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc13-ada", rpm:"gcc13-ada~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libm2log18-debuginfo", rpm:"libm2log18-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-locale", rpm:"libstdc++6-locale~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libm2iso18", rpm:"libm2iso18~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblsan0-debuginfo", rpm:"liblsan0-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc13-locale", rpm:"gcc13-locale~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libubsan1-debuginfo", rpm:"libubsan1-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc13-c++-debuginfo", rpm:"gcc13-c++-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc13-m2-debuginfo", rpm:"gcc13-m2-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libm2min18-debuginfo", rpm:"libm2min18-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblsan0", rpm:"liblsan0~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-devel-gcc13", rpm:"libstdc++6-devel-gcc13~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libm2log18", rpm:"libm2log18~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc13-go-debuginfo", rpm:"gcc13-go-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libm2min18", rpm:"libm2min18~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasan8", rpm:"libasan8~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cpp13", rpm:"cpp13~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc13-objc-debuginfo", rpm:"gcc13-objc-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6", rpm:"libstdc++6~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libm2iso18-debuginfo", rpm:"libm2iso18-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc13", rpm:"gcc13~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc13-c++", rpm:"gcc13-c++~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasan8-debuginfo", rpm:"libasan8-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libm2pim18-debuginfo", rpm:"libm2pim18-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc13-obj-c++-debuginfo", rpm:"gcc13-obj-c++-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcc_s1-debuginfo", rpm:"libgcc_s1-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcc_s1", rpm:"libgcc_s1~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libitm1", rpm:"libitm1~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libada13-debuginfo", rpm:"libada13-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgfortran5-debuginfo", rpm:"libgfortran5-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtsan2", rpm:"libtsan2~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-nvptx-newlib13-devel", rpm:"cross-nvptx-newlib13-devel~13.2.1+git7813~150000.1.3.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-nvptx-gcc13", rpm:"cross-nvptx-gcc13~13.2.1+git7813~150000.1.3.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquadmath0-32bit", rpm:"libquadmath0-32bit~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-nvptx-gcc13-debugsource", rpm:"cross-nvptx-gcc13-debugsource~13.2.1+git7813~150000.1.3.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquadmath0-32bit-debuginfo", rpm:"libquadmath0-32bit-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-nvptx-gcc13-debuginfo", rpm:"cross-nvptx-gcc13-debuginfo~13.2.1+git7813~150000.1.3.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgo22-32bit", rpm:"libgo22-32bit~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libm2pim18-32bit-debuginfo", rpm:"libm2pim18-32bit-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgomp1-32bit-debuginfo", rpm:"libgomp1-32bit-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasan8-32bit", rpm:"libasan8-32bit~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgphobos4-32bit", rpm:"libgphobos4-32bit~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libitm1-32bit", rpm:"libitm1-32bit~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libm2cor18-32bit-debuginfo", rpm:"libm2cor18-32bit-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasan8-32bit-debuginfo", rpm:"libasan8-32bit-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcc_s1-32bit", rpm:"libgcc_s1-32bit~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libm2log18-32bit-debuginfo", rpm:"libm2log18-32bit-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libobjc4-32bit", rpm:"libobjc4-32bit~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc13-d-32bit", rpm:"gcc13-d-32bit~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc13-go-32bit", rpm:"gcc13-go-32bit~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libubsan1-32bit-debuginfo", rpm:"libubsan1-32bit-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libatomic1-32bit", rpm:"libatomic1-32bit~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-32bit", rpm:"libstdc++6-32bit~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-32bit-debuginfo", rpm:"libstdc++6-32bit-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc13-objc-32bit", rpm:"gcc13-objc-32bit~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc13-m2-32bit", rpm:"gcc13-m2-32bit~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgdruntime4-32bit-debuginfo", rpm:"libgdruntime4-32bit-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libm2iso18-32bit", rpm:"libm2iso18-32bit~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libobjc4-32bit-debuginfo", rpm:"libobjc4-32bit-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgdruntime4-32bit", rpm:"libgdruntime4-32bit~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc13-32bit", rpm:"gcc13-32bit~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libm2iso18-32bit-debuginfo", rpm:"libm2iso18-32bit-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libubsan1-32bit", rpm:"libubsan1-32bit~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libada13-32bit", rpm:"libada13-32bit~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc13-ada-32bit", rpm:"gcc13-ada-32bit~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libitm1-32bit-debuginfo", rpm:"libitm1-32bit-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-pp-32bit", rpm:"libstdc++6-pp-32bit~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libada13-32bit-debuginfo", rpm:"libada13-32bit-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgfortran5-32bit", rpm:"libgfortran5-32bit~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libm2min18-32bit-debuginfo", rpm:"libm2min18-32bit-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc13-obj-c++-32bit", rpm:"gcc13-obj-c++-32bit~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgomp1-32bit", rpm:"libgomp1-32bit~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libm2cor18-32bit", rpm:"libm2cor18-32bit~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcc_s1-32bit-debuginfo", rpm:"libgcc_s1-32bit-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgfortran5-32bit-debuginfo", rpm:"libgfortran5-32bit-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libm2min18-32bit", rpm:"libm2min18-32bit~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgphobos4-32bit-debuginfo", rpm:"libgphobos4-32bit-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc13-c++-32bit", rpm:"gcc13-c++-32bit~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgo22-32bit-debuginfo", rpm:"libgo22-32bit-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libm2pim18-32bit", rpm:"libm2pim18-32bit~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-devel-gcc13-32bit", rpm:"libstdc++6-devel-gcc13-32bit~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libm2log18-32bit", rpm:"libm2log18-32bit~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libatomic1-32bit-debuginfo", rpm:"libatomic1-32bit-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc13-fortran-32bit", rpm:"gcc13-fortran-32bit~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgphobos4", rpm:"libgphobos4~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc13-d-debuginfo", rpm:"gcc13-d-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgdruntime4", rpm:"libgdruntime4~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc13-d", rpm:"gcc13-d~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgdruntime4-debuginfo", rpm:"libgdruntime4-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgphobos4-debuginfo", rpm:"libgphobos4-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc13-info", rpm:"gcc13-info~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhwasan0-debuginfo", rpm:"libhwasan0-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhwasan0", rpm:"libhwasan0~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquadmath0-debuginfo", rpm:"libquadmath0-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquadmath0", rpm:"libquadmath0~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }


  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeapMicro5.3") {

  if(!isnull(res = isrpmvuln(pkg:"gcc13-debuginfo", rpm:"gcc13-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc13-debugsource", rpm:"gcc13-debugsource~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6", rpm:"libstdc++6~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcc_s1-debuginfo", rpm:"libgcc_s1-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-debuginfo", rpm:"libstdc++6-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcc_s1", rpm:"libgcc_s1~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeapMicro5.4") {

  if(!isnull(res = isrpmvuln(pkg:"gcc13-debuginfo", rpm:"gcc13-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc13-debugsource", rpm:"gcc13-debugsource~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6", rpm:"libstdc++6~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcc_s1-debuginfo", rpm:"libgcc_s1-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-debuginfo", rpm:"libstdc++6-debuginfo~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcc_s1", rpm:"libgcc_s1~13.2.1+git7813~150000.1.3.3", rls:"openSUSELeapMicro5.4"))) {
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
