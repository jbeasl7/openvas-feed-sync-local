# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.2779.1");
  script_cve_id("CVE-2018-1000876", "CVE-2018-17358", "CVE-2018-17359", "CVE-2018-17360", "CVE-2018-17985", "CVE-2018-18309", "CVE-2018-18483", "CVE-2018-18484", "CVE-2018-18605", "CVE-2018-18606", "CVE-2018-18607", "CVE-2018-19931", "CVE-2018-19932", "CVE-2018-20623", "CVE-2018-20651", "CVE-2018-20671", "CVE-2018-6323", "CVE-2018-6543", "CVE-2018-6759", "CVE-2018-6872", "CVE-2018-7208", "CVE-2018-7568", "CVE-2018-7569", "CVE-2018-7570", "CVE-2018-7642", "CVE-2018-7643", "CVE-2018-8945", "CVE-2019-1010180");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:14 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-01 15:39:30 +0000 (Thu, 01 Aug 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:2779-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:2779-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20192779-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'binutils' package(s) announced via the SUSE-SU-2019:2779-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for binutils fixes the following issues:

binutils was updated to current 2.32 branch [jsc#ECO-368].

Includes following security fixes:
CVE-2018-17358: Fixed invalid memory access in
 _bfd_stab_section_find_nearest_line in syms.c (bsc#1109412)

CVE-2018-17359: Fixed invalid memory access exists in bfd_zalloc in
 opncls.c (bsc#1109413)

CVE-2018-17360: Fixed heap-based buffer over-read in bfd_getl32 in
 libbfd.c (bsc#1109414)

CVE-2018-17985: Fixed a stack consumption problem caused by the
 cplus_demangle_type (bsc#1116827)

CVE-2018-18309: Fixed an invalid memory address dereference was
 discovered in read_reloc in reloc.c (bsc#1111996)

CVE-2018-18483: Fixed get_count function provided by libiberty that
 allowed attackers to cause a denial of service or other unspecified
 impact (bsc#1112535)

CVE-2018-18484: Fixed stack exhaustion in the C++ demangling functions
 provided by libiberty, caused by recursive stack frames (bsc#1112534)

CVE-2018-18605: Fixed a heap-based buffer over-read issue was discovered
 in the function sec_merge_hash_lookup causing a denial of service
 (bsc#1113255)

CVE-2018-18606: Fixed a NULL pointer dereference in
 _bfd_add_merge_section when attempting to merge sections with large
 alignments, causing denial of service (bsc#1113252)

CVE-2018-18607: Fixed a NULL pointer dereference in elf_link_input_bfd
 when used for finding STT_TLS symbols without any TLS section, causing
 denial of service (bsc#1113247)

CVE-2018-19931: Fixed a heap-based buffer overflow in
 bfd_elf32_swap_phdr_in in elfcode.h (bsc#1118831)

CVE-2018-19932: Fixed an integer overflow and infinite loop caused by
 the IS_CONTAINED_BY_LMA (bsc#1118830)

CVE-2018-20623: Fixed a use-after-free in the error function in
 elfcomm.c (bsc#1121035)

CVE-2018-20651: Fixed a denial of service via a NULL pointer dereference
 in elf_link_add_object_symbols in elflink.c (bsc#1121034)

CVE-2018-20671: Fixed an integer overflow that can trigger a heap-based
 buffer overflow in load_specific_debug_section in objdump.c
 (bsc#1121056)

CVE-2018-1000876: Fixed integer overflow in
 bfd_get_dynamic_reloc_upper_bound,bfd_canonicalize_dynamic_reloc in
 objdump (bsc#1120640)

CVE-2019-1010180: Fixed an out of bound memory access that could lead to
 crashes (bsc#1142772)
enable xtensa architecture (Tensilica lc6 and related)

Use -ffat-lto-objects in order to provide assembly for static libs
 (bsc#1141913).

Fixed some LTO build issues (bsc#1133131 bsc#1133232).

riscv: Don't check ABI flags if no code section

Fixed a segfault in ld when building some versions of pacemaker
 (bsc#1154025, bsc#1154016).

Add avr, epiphany and rx to target_list so that the common binutils can
 handle all objects we can create with crosses (bsc#1152590).

Update to binutils 2.32:
The binutils now support for the C-SKY processor series.

The x86 assembler now supports a -mvexwig=[0<pipe>1] option to control
 ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'binutils' package(s) on SUSE Linux Enterprise Module for Basesystem 15-SP1, SUSE Linux Enterprise Module for Development Tools 15-SP1, SUSE Linux Enterprise Module for Open Buildservice Development Tools 15-SP1, SUSE Linux Enterprise Module for Packagehub Subpackages 15-SP1.");

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

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"binutils", rpm:"binutils~2.32~7.5.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-debuginfo", rpm:"binutils-debuginfo~2.32~7.5.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-debugsource", rpm:"binutils-debugsource~2.32~7.5.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-devel", rpm:"binutils-devel~2.32~7.5.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-devel-32bit", rpm:"binutils-devel-32bit~2.32~7.5.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-gold", rpm:"binutils-gold~2.32~7.5.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-gold-debuginfo", rpm:"binutils-gold-debuginfo~2.32~7.5.1", rls:"SLES15.0SP1"))) {
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
