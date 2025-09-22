# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.3170.1");
  script_cve_id("CVE-2017-15938", "CVE-2017-15939", "CVE-2017-15996", "CVE-2017-16826", "CVE-2017-16827", "CVE-2017-16828", "CVE-2017-16829", "CVE-2017-16830", "CVE-2017-16831", "CVE-2017-16832", "CVE-2018-10372", "CVE-2018-10373", "CVE-2018-10534", "CVE-2018-10535", "CVE-2018-6323", "CVE-2018-6543", "CVE-2018-6759", "CVE-2018-6872", "CVE-2018-7208", "CVE-2018-7568", "CVE-2018-7569", "CVE-2018-7570", "CVE-2018-7642", "CVE-2018-7643", "CVE-2018-8945");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:36 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-19 16:46:19 +0000 (Mon, 19 Mar 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:3170-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:3170-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20183170-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'binutils' package(s) announced via the SUSE-SU-2018:3170-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for binutils to version 2.31 fixes the following issues:

These security issues were fixed:
CVE-2017-15996: readelf allowed remote attackers to cause a denial of
 service (excessive memory allocation) or possibly have unspecified other
 impact via a crafted ELF file that triggered a buffer overflow on fuzzed
 archive header (bsc#1065643)

CVE-2017-15939: Binary File Descriptor (BFD) library (aka libbfd)
 mishandled NULL files in a .debug_line file table, which allowed remote
 attackers to cause a denial of service (NULL pointer dereference and
 application crash) via a crafted ELF file, related to concat_filename
 (bsc#1065689)

CVE-2017-15938: the Binary File Descriptor (BFD) library (aka libbfd)
 miscalculated DW_FORM_ref_addr die refs in the case of a relocatable
 object file, which allowed remote attackers to cause a denial of service
 (find_abstract_instance_name invalid memory read, segmentation fault,
 and application crash) (bsc#1065693)

CVE-2017-16826: The coff_slurp_line_table function the Binary File
 Descriptor (BFD) library (aka libbfd) allowed remote attackers to cause
 a denial of service (invalid memory access and application crash) or
 possibly have unspecified other impact via a crafted PE file
 (bsc#1068640)

CVE-2017-16832: The pe_bfd_read_buildid function in the Binary File
 Descriptor (BFD) library (aka libbfd) did not validate size and offset
 values in the data dictionary, which allowed remote attackers to cause a
 denial of service (segmentation violation and application crash) or
 possibly have unspecified other impact via a crafted PE file
 (bsc#1068643)

CVE-2017-16831: Binary File Descriptor (BFD) library (aka libbfd) did
 not validate the symbol count, which allowed remote attackers to cause a
 denial of service (integer overflow and application crash, or excessive
 memory allocation) or possibly have unspecified other impact via a
 crafted PE file (bsc#1068887)

CVE-2017-16830: The print_gnu_property_note function did not have
 integer-overflow protection on 32-bit platforms, which allowed remote
 attackers to cause a denial of service (segmentation violation and
 application crash) or possibly have unspecified other impact via a
 crafted ELF file (bsc#1068888)

CVE-2017-16829: The _bfd_elf_parse_gnu_properties function in the Binary
 File Descriptor (BFD) library (aka libbfd) did not prevent negative
 pointers, which allowed remote attackers to cause a denial of service
 (out-of-bounds read and application crash) or possibly have unspecified
 other impact via a crafted ELF file (bsc#1068950)

CVE-2017-16828: The display_debug_frames function allowed remote
 attackers to cause a denial of service (integer overflow and heap-based
 buffer over-read, and application crash) or possibly have unspecified
 other impact via a crafted ELF file (bsc#1069176)

CVE-2017-16827: The aout_get_external_symbols function in the Binary
 File ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'binutils' package(s) on SUSE Linux Enterprise Module for Basesystem 15, SUSE Linux Enterprise Module for Development Tools 15.");

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

  if(!isnull(res = isrpmvuln(pkg:"binutils", rpm:"binutils~2.31~6.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-debuginfo", rpm:"binutils-debuginfo~2.31~6.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-debugsource", rpm:"binutils-debugsource~2.31~6.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-devel", rpm:"binutils-devel~2.31~6.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-devel-32bit", rpm:"binutils-devel-32bit~2.31~6.3.1", rls:"SLES15.0"))) {
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
