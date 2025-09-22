# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833308");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2020-19726", "CVE-2021-32256", "CVE-2022-35205", "CVE-2022-35206", "CVE-2022-4285", "CVE-2022-44840", "CVE-2022-45703", "CVE-2022-47673", "CVE-2022-47695", "CVE-2022-47696", "CVE-2022-48063", "CVE-2022-48064", "CVE-2022-48065", "CVE-2023-0687", "CVE-2023-1579", "CVE-2023-1972", "CVE-2023-2222", "CVE-2023-25585", "CVE-2023-25587", "CVE-2023-25588");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:H/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-14 18:52:59 +0000 (Tue, 14 Feb 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:19:32 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for binutils (SUSE-SU-2023:3825-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:3825-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/LKILMMNAFKRO2UTMGPZUO2PWSTSHEB62");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'binutils'
  package(s) announced via the SUSE-SU-2023:3825-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for binutils fixes the following issues:

  Update to version 2.41 [jsc#PED-5778]:

  * The MIPS port now supports the Sony Interactive Entertainment Allegrex
      processor, used with the PlayStation Portable, which implements the MIPS II
      ISA along with a single-precision FPU and a few implementation-specific
      integer instructions.

  * Objdump's --private option can now be used on PE format files to display the
      fields in the file header and section headers.

  * New versioned release of libsframe: libsframe.so.1. This release introduces
      versioned symbols with version node name LIBSFRAME_1.0. This release also
      updates the ABI in an incompatible way: this includes removal of
      sframe_get_funcdesc_with_addr API, change in the behavior of
      sframe_fre_get_ra_offset and sframe_fre_get_fp_offset APIs.

  * SFrame Version 2 is now the default (and only) format version supported by
      gas, ld, readelf and objdump.

  * Add command-line option, --strip-section-headers, to objcopy and strip to
      remove ELF section header from ELF file.

  * The RISC-V port now supports the following new standard extensions:

  * Zicond (conditional zero instructions)

  * Zfa (additional floating-point instructions)

  * Zvbb, Zvbc, Zvkg, Zvkned, Zvknh[ab], Zvksed, Zvksh, Zvkn, Zvknc, Zvkng,
      Zvks, Zvksc, Zvkg, Zvkt (vector crypto instructions)

  * The RISC-V port now supports the following vendor-defined extensions:

  * XVentanaCondOps

  * Add support for Intel FRED, LKGS and AMX-COMPLEX instructions.

  * A new .insn directive is recognized by x86 gas.

  * Add SME2 support to the AArch64 port.

  * The linker now accepts a command line option of --remap-inputs
       PATTERN = FILE  to relace any input file that matches  PATTERN  with
       FILE. In addition the option --remap-inputs-file= FILE  can be used to
      specify a file containing any number of these remapping directives.

  * The linker command line option --print-map-locals can be used to include
      local symbols in a linker map. (ELF targets only).

  * For most ELF based targets, if the --enable-linker-version option is used
      then the version of the linker will be inserted as a string into the
      .comment section.

  * The linker script syntax has a new command for output sections: ASCIZ
      'string' This will insert a zero-terminated string at the current location.

  * Add command-line option, -z nosectionheader, to omit ELF section header.

  * Contains fixes for these non-CVEs (not security bugs per upstreams
  ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'binutils' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5.");

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

  if(!isnull(res = isrpmvuln(pkg:"libctf-nobfd0", rpm:"libctf-nobfd0~2.41~150100.7.46.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-debugsource", rpm:"binutils-debugsource~2.41~150100.7.46.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-debuginfo", rpm:"binutils-debuginfo~2.41~150100.7.46.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-gold", rpm:"binutils-gold~2.41~150100.7.46.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libctf0", rpm:"libctf0~2.41~150100.7.46.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libctf-nobfd0-debuginfo", rpm:"libctf-nobfd0-debuginfo~2.41~150100.7.46.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libctf0-debuginfo", rpm:"libctf0-debuginfo~2.41~150100.7.46.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils", rpm:"binutils~2.41~150100.7.46.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-devel", rpm:"binutils-devel~2.41~150100.7.46.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-gold-debuginfo", rpm:"binutils-gold-debuginfo~2.41~150100.7.46.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-devel-32bit", rpm:"binutils-devel-32bit~2.41~150100.7.46.1##", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libctf-nobfd0", rpm:"libctf-nobfd0~2.41~150100.7.46.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-debugsource", rpm:"binutils-debugsource~2.41~150100.7.46.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-debuginfo", rpm:"binutils-debuginfo~2.41~150100.7.46.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-gold", rpm:"binutils-gold~2.41~150100.7.46.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libctf0", rpm:"libctf0~2.41~150100.7.46.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libctf-nobfd0-debuginfo", rpm:"libctf-nobfd0-debuginfo~2.41~150100.7.46.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libctf0-debuginfo", rpm:"libctf0-debuginfo~2.41~150100.7.46.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils", rpm:"binutils~2.41~150100.7.46.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-devel", rpm:"binutils-devel~2.41~150100.7.46.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-gold-debuginfo", rpm:"binutils-gold-debuginfo~2.41~150100.7.46.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-devel-32bit", rpm:"binutils-devel-32bit~2.41~150100.7.46.1##", rls:"openSUSELeap15.4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"cross-hppa64-binutils-debugsource", rpm:"cross-hppa64-binutils-debugsource~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-sparc-binutils-debuginfo", rpm:"cross-sparc-binutils-debuginfo~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-hppa64-binutils-debuginfo", rpm:"cross-hppa64-binutils-debuginfo~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-hppa-binutils-debugsource", rpm:"cross-hppa-binutils-debugsource~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-sparc-binutils", rpm:"cross-sparc-binutils~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-gold", rpm:"binutils-gold~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-ia64-binutils", rpm:"cross-ia64-binutils~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-spu-binutils-debuginfo", rpm:"cross-spu-binutils-debuginfo~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-avr-binutils", rpm:"cross-avr-binutils~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-sparc64-binutils", rpm:"cross-sparc64-binutils~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libctf-nobfd0-debuginfo", rpm:"libctf-nobfd0-debuginfo~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-sparc64-binutils-debuginfo", rpm:"cross-sparc64-binutils-debuginfo~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-s390-binutils-debugsource", rpm:"cross-s390-binutils-debugsource~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-xtensa-binutils", rpm:"cross-xtensa-binutils~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-ppc-binutils", rpm:"cross-ppc-binutils~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-ppc-binutils-debugsource", rpm:"cross-ppc-binutils-debugsource~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-epiphany-binutils", rpm:"cross-epiphany-binutils~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-i386-binutils-debuginfo", rpm:"cross-i386-binutils-debuginfo~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-riscv64-binutils", rpm:"cross-riscv64-binutils~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-ppc64-binutils-debugsource", rpm:"cross-ppc64-binutils-debugsource~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-sparc64-binutils-debugsource", rpm:"cross-sparc64-binutils-debugsource~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-hppa64-binutils", rpm:"cross-hppa64-binutils~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-arm-binutils-debuginfo", rpm:"cross-arm-binutils-debuginfo~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-arm-binutils-debugsource", rpm:"cross-arm-binutils-debugsource~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-m68k-binutils-debuginfo", rpm:"cross-m68k-binutils-debuginfo~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-rx-binutils", rpm:"cross-rx-binutils~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libctf-nobfd0", rpm:"libctf-nobfd0~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-xtensa-binutils-debuginfo", rpm:"cross-xtensa-binutils-debuginfo~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-i386-binutils-debugsource", rpm:"cross-i386-binutils-debugsource~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-spu-binutils-debugsource", rpm:"cross-spu-binutils-debugsource~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-epiphany-binutils-debuginfo", rpm:"cross-epiphany-binutils-debuginfo~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils", rpm:"binutils~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-riscv64-binutils-debugsource", rpm:"cross-riscv64-binutils-debugsource~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-ia64-binutils-debugsource", rpm:"cross-ia64-binutils-debugsource~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-gold-debuginfo", rpm:"binutils-gold-debuginfo~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-rx-binutils-debugsource", rpm:"cross-rx-binutils-debugsource~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-debuginfo", rpm:"binutils-debuginfo~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-m68k-binutils", rpm:"cross-m68k-binutils~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-mips-binutils-debuginfo", rpm:"cross-mips-binutils-debuginfo~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-hppa-binutils", rpm:"cross-hppa-binutils~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-ppc64-binutils-debuginfo", rpm:"cross-ppc64-binutils-debuginfo~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-i386-binutils", rpm:"cross-i386-binutils~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libctf0-debuginfo", rpm:"libctf0-debuginfo~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-ia64-binutils-debuginfo", rpm:"cross-ia64-binutils-debuginfo~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-rx-binutils-debuginfo", rpm:"cross-rx-binutils-debuginfo~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-xtensa-binutils-debugsource", rpm:"cross-xtensa-binutils-debugsource~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-hppa-binutils-debuginfo", rpm:"cross-hppa-binutils-debuginfo~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-ppc64-binutils", rpm:"cross-ppc64-binutils~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-epiphany-binutils-debugsource", rpm:"cross-epiphany-binutils-debugsource~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-debugsource", rpm:"binutils-debugsource~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-sparc-binutils-debugsource", rpm:"cross-sparc-binutils-debugsource~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-avr-binutils-debugsource", rpm:"cross-avr-binutils-debugsource~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-avr-binutils-debuginfo", rpm:"cross-avr-binutils-debuginfo~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libctf0", rpm:"libctf0~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-m68k-binutils-debugsource", rpm:"cross-m68k-binutils-debugsource~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-spu-binutils", rpm:"cross-spu-binutils~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-arm-binutils", rpm:"cross-arm-binutils~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-ppc-binutils-debuginfo", rpm:"cross-ppc-binutils-debuginfo~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-s390-binutils", rpm:"cross-s390-binutils~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-devel", rpm:"binutils-devel~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-s390-binutils-debuginfo", rpm:"cross-s390-binutils-debuginfo~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-mips-binutils-debugsource", rpm:"cross-mips-binutils-debugsource~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-mips-binutils", rpm:"cross-mips-binutils~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-riscv64-binutils-debuginfo", rpm:"cross-riscv64-binutils-debuginfo~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-devel-32bit", rpm:"binutils-devel-32bit~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-aarch64-binutils-debugsource", rpm:"cross-aarch64-binutils-debugsource~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-aarch64-binutils-debuginfo", rpm:"cross-aarch64-binutils-debuginfo~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-aarch64-binutils", rpm:"cross-aarch64-binutils~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-ppc64le-binutils-debuginfo", rpm:"cross-ppc64le-binutils-debuginfo~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-ppc64le-binutils", rpm:"cross-ppc64le-binutils~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-ppc64le-binutils-debugsource", rpm:"cross-ppc64le-binutils-debugsource~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-s390x-binutils-debugsource", rpm:"cross-s390x-binutils-debugsource~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-s390x-binutils", rpm:"cross-s390x-binutils~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-s390x-binutils-debuginfo", rpm:"cross-s390x-binutils-debuginfo~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-x86_64-binutils-debugsource", rpm:"cross-x86_64-binutils-debugsource~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-x86_64-binutils-debuginfo", rpm:"cross-x86_64-binutils-debuginfo~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-x86_64-binutils", rpm:"cross-x86_64-binutils~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-hppa64-binutils-debugsource", rpm:"cross-hppa64-binutils-debugsource~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-sparc-binutils-debuginfo", rpm:"cross-sparc-binutils-debuginfo~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-hppa64-binutils-debuginfo", rpm:"cross-hppa64-binutils-debuginfo~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-hppa-binutils-debugsource", rpm:"cross-hppa-binutils-debugsource~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-sparc-binutils", rpm:"cross-sparc-binutils~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-gold", rpm:"binutils-gold~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-ia64-binutils", rpm:"cross-ia64-binutils~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-spu-binutils-debuginfo", rpm:"cross-spu-binutils-debuginfo~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-avr-binutils", rpm:"cross-avr-binutils~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-sparc64-binutils", rpm:"cross-sparc64-binutils~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libctf-nobfd0-debuginfo", rpm:"libctf-nobfd0-debuginfo~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-sparc64-binutils-debuginfo", rpm:"cross-sparc64-binutils-debuginfo~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-s390-binutils-debugsource", rpm:"cross-s390-binutils-debugsource~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-xtensa-binutils", rpm:"cross-xtensa-binutils~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-ppc-binutils", rpm:"cross-ppc-binutils~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-ppc-binutils-debugsource", rpm:"cross-ppc-binutils-debugsource~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-epiphany-binutils", rpm:"cross-epiphany-binutils~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-i386-binutils-debuginfo", rpm:"cross-i386-binutils-debuginfo~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-riscv64-binutils", rpm:"cross-riscv64-binutils~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-ppc64-binutils-debugsource", rpm:"cross-ppc64-binutils-debugsource~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-sparc64-binutils-debugsource", rpm:"cross-sparc64-binutils-debugsource~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-hppa64-binutils", rpm:"cross-hppa64-binutils~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-arm-binutils-debuginfo", rpm:"cross-arm-binutils-debuginfo~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-arm-binutils-debugsource", rpm:"cross-arm-binutils-debugsource~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-m68k-binutils-debuginfo", rpm:"cross-m68k-binutils-debuginfo~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-rx-binutils", rpm:"cross-rx-binutils~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libctf-nobfd0", rpm:"libctf-nobfd0~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-xtensa-binutils-debuginfo", rpm:"cross-xtensa-binutils-debuginfo~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-i386-binutils-debugsource", rpm:"cross-i386-binutils-debugsource~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-spu-binutils-debugsource", rpm:"cross-spu-binutils-debugsource~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-epiphany-binutils-debuginfo", rpm:"cross-epiphany-binutils-debuginfo~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils", rpm:"binutils~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-riscv64-binutils-debugsource", rpm:"cross-riscv64-binutils-debugsource~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-ia64-binutils-debugsource", rpm:"cross-ia64-binutils-debugsource~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-gold-debuginfo", rpm:"binutils-gold-debuginfo~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-rx-binutils-debugsource", rpm:"cross-rx-binutils-debugsource~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-debuginfo", rpm:"binutils-debuginfo~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-m68k-binutils", rpm:"cross-m68k-binutils~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-mips-binutils-debuginfo", rpm:"cross-mips-binutils-debuginfo~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-hppa-binutils", rpm:"cross-hppa-binutils~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-ppc64-binutils-debuginfo", rpm:"cross-ppc64-binutils-debuginfo~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-i386-binutils", rpm:"cross-i386-binutils~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libctf0-debuginfo", rpm:"libctf0-debuginfo~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-ia64-binutils-debuginfo", rpm:"cross-ia64-binutils-debuginfo~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-rx-binutils-debuginfo", rpm:"cross-rx-binutils-debuginfo~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-xtensa-binutils-debugsource", rpm:"cross-xtensa-binutils-debugsource~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-hppa-binutils-debuginfo", rpm:"cross-hppa-binutils-debuginfo~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-ppc64-binutils", rpm:"cross-ppc64-binutils~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-epiphany-binutils-debugsource", rpm:"cross-epiphany-binutils-debugsource~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-debugsource", rpm:"binutils-debugsource~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-sparc-binutils-debugsource", rpm:"cross-sparc-binutils-debugsource~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-avr-binutils-debugsource", rpm:"cross-avr-binutils-debugsource~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-avr-binutils-debuginfo", rpm:"cross-avr-binutils-debuginfo~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libctf0", rpm:"libctf0~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-m68k-binutils-debugsource", rpm:"cross-m68k-binutils-debugsource~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-spu-binutils", rpm:"cross-spu-binutils~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-arm-binutils", rpm:"cross-arm-binutils~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-ppc-binutils-debuginfo", rpm:"cross-ppc-binutils-debuginfo~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-s390-binutils", rpm:"cross-s390-binutils~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-devel", rpm:"binutils-devel~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-s390-binutils-debuginfo", rpm:"cross-s390-binutils-debuginfo~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-mips-binutils-debugsource", rpm:"cross-mips-binutils-debugsource~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-mips-binutils", rpm:"cross-mips-binutils~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-riscv64-binutils-debuginfo", rpm:"cross-riscv64-binutils-debuginfo~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-devel-32bit", rpm:"binutils-devel-32bit~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-aarch64-binutils-debugsource", rpm:"cross-aarch64-binutils-debugsource~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-aarch64-binutils-debuginfo", rpm:"cross-aarch64-binutils-debuginfo~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-aarch64-binutils", rpm:"cross-aarch64-binutils~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-ppc64le-binutils-debuginfo", rpm:"cross-ppc64le-binutils-debuginfo~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-ppc64le-binutils", rpm:"cross-ppc64le-binutils~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-ppc64le-binutils-debugsource", rpm:"cross-ppc64le-binutils-debugsource~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-s390x-binutils-debugsource", rpm:"cross-s390x-binutils-debugsource~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-s390x-binutils", rpm:"cross-s390x-binutils~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-s390x-binutils-debuginfo", rpm:"cross-s390x-binutils-debuginfo~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-x86_64-binutils-debugsource", rpm:"cross-x86_64-binutils-debugsource~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-x86_64-binutils-debuginfo", rpm:"cross-x86_64-binutils-debuginfo~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-x86_64-binutils", rpm:"cross-x86_64-binutils~2.41~150100.7.46.1", rls:"openSUSELeap15.5"))) {
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