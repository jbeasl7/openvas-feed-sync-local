# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.3552.1");
  script_cve_id("CVE-2019-12972", "CVE-2019-14250", "CVE-2019-14444", "CVE-2019-17450", "CVE-2019-17451", "CVE-2019-9074", "CVE-2019-9075", "CVE-2019-9077");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-02-25 18:38:54 +0000 (Mon, 25 Feb 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:3552-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:3552-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20203552-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1126826");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1126829");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1126831");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140126");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1142649");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1143609");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1153768");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1153770");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157755");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1160254");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1160590");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1163333");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1163744");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179036");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2020-November/007888.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'binutils' package(s) announced via the SUSE-SU-2020:3552-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for binutils fixes the following issues:

binutils was updated to version 2.35.1 (jsc#ECO-2373)

Additional branch fixes applied on top of 2.35.1:

* Fixes PR26520, aka [bsc#1179036], a problem in addr2line with
 certain DWARF variable descriptions.
* Also fixes PR26711, PR26656, PR26655, PR26929, PR26808, PR25878,
 PR26740, PR26778, PR26763, PR26685, PR26699, PR26902, PR26869,
 PR26711
* The above includes fixes for dwo files produced by modern dwp,
 fixing several problems in the DWARF reader.

Update to binutils 2.35.1 and rebased branch diff:

* This is a point release over the previous 2.35 version, containing bug
 fixes, and as an exception to the usual rule, one new feature. The
 new feature is the support for a new directive in the assembler:
 '.nop'. This directive creates a single no-op instruction in whatever
 encoding is correct for the target architecture. Unlike the .space or
 .fill this is a real instruction, and it does affect the generation of
 DWARF line number tables, should they be enabled.

Update to binutils 2.35:

* The assembler can now produce DWARF-5 format line number tables.
* Readelf now has a 'lint' mode to enable extra checks of the files it is processing.
* Readelf will now display '[...]' when it has to truncate a symbol name.
 The old behaviour - of displaying as many characters as possible, up to
 the 80 column limit - can be restored by the use of the --silent-truncation
 option.
* The linker can now produce a dependency file listing the inputs that it
 has processed, much like the -M -MP option supported by the compiler.

- fix DT_NEEDED order with -flto [bsc#1163744]


Update to binutils 2.34:

* The disassembler (objdump --disassemble) now has an option to
 generate ascii art thats show the arcs between that start and end
 points of control flow instructions.
* The binutils tools now have support for debuginfod. Debuginfod is a
 HTTP service for distributing ELF/DWARF debugging information as
 well as source code. The tools can now connect to debuginfod
 servers in order to download debug information about the files that
 they are processing.
* The assembler and linker now support the generation of ELF format
 files for the Z80 architecture.

- Add new subpackages for libctf and libctf-nobfd.
- Disable LTO due to bsc#1163333.
- Includes fixes for these CVEs:
 bsc#1153768 aka CVE-2019-17451 aka PR25070
 bsc#1153770 aka CVE-2019-17450 aka PR25078

- fix various build fails on aarch64 (PR25210, bsc#1157755).

Update to binutils 2.33.1:

* Adds support for the Arm Scalable Vector Extension version 2
 (SVE2) instructions, the Arm Transactional Memory Extension (TME)
 instructions and the Armv8.1-M Mainline and M-profile Vector
 Extension (MVE) instructions.
* Adds support for the Arm Cortex-A76AE, Cortex-A77 and Cortex-M35P
 processors and the AArch64 Cortex-A34, Cortex-A65, Cortex-A65AE,
 Cortex-A76AE, and Cortex-A77 ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'binutils' package(s) on SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server for SAP Applications 15.");

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

  if(!isnull(res = isrpmvuln(pkg:"binutils", rpm:"binutils~2.35.1~6.15.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-devel", rpm:"binutils-devel~2.35.1~6.15.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-devel-32bit", rpm:"binutils-devel-32bit~2.35.1~6.15.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libctf-nobfd0", rpm:"libctf-nobfd0~2.35.1~6.15.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libctf0", rpm:"libctf0~2.35.1~6.15.1", rls:"SLES15.0"))) {
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
