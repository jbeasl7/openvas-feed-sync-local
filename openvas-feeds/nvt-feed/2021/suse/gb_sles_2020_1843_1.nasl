# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.1843.1");
  script_cve_id("CVE-2018-1000667", "CVE-2018-10016", "CVE-2018-10254", "CVE-2018-10316", "CVE-2018-16382", "CVE-2018-16517", "CVE-2018-16999", "CVE-2018-19214", "CVE-2018-19215", "CVE-2018-19216", "CVE-2018-8881", "CVE-2018-8882", "CVE-2018-8883");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:00 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-04-12 12:34:23 +0000 (Thu, 12 Apr 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:1843-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1|SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:1843-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20201843-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nasm' package(s) announced via the SUSE-SU-2020:1843-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for nasm fixes the following issues:

nasm was updated to version 2.14.02.

This allows building of Mozilla Firefox 78ESR and also contains lots of bugfixes, security fixes and improvements.

Fix crash due to multiple errors or warnings during the code generation
 pass if a list file is specified.

Create all system-defined macros defore processing command-line given
 preprocessing directives (-p, -d, -u, --pragma, --before).

If debugging is enabled, define a __DEBUG_FORMAT__ predefined macro. See
 section 4.11.7.

Fix an assert for the case in the obj format when a SEG operator refers
 to an EXTERN symbol declared further down in the code.

Fix a corner case in the floating-point code where a binary, octal or
 hexadecimal floating-point having at least 32, 11, or 8 mantissa digits
 could produce slightly incorrect results under very specific conditions.

Support -MD without a filename, for gcc compatibility. -MF can be used
 to set the dependencies output filename. See section 2.1.7.

Fix -E in combination with -MD. See section 2.1.21.

Fix missing errors on redefined labels, would cause convergence failure
 instead which is very slow and not easy to debug.

Duplicate definitions of the same label with the same value is now
 explicitly permitted (2.14 would allow it in some circumstances.)

Add the option --no-line to ignore %line directives in the source. See
 section 2.1.33 and section 4.10.1.

Changed -I option semantics by adding a trailing path separator
 unconditionally.

Fixed null dereference in corrupted invalid single line macros.

Fixed division by zero which may happen if source code is malformed.

Fixed out of bound access in processing of malformed segment override.

Fixed out of bound access in certain EQU parsing.

Fixed buffer underflow in float parsing.

Added SGX (Intel Software Guard Extensions) instructions.

Added +n syntax for multiple contiguous registers.

Fixed subsections_via_symbols for macho object format.

Added the --gprefix, --gpostfix, --lprefix, and --lpostfix command line
 options, to allow command line base symbol renaming. See section 2.1.28.

Allow label renaming to be specified by %pragma in addition to from the
 command line. See section 6.9.

Supported generic %pragma namespaces, output and debug. See section 6.10.

Added the --pragma command line option to inject a %pragma directive.
 See section 2.1.29.

Added the --before command line option to accept preprocess statement
 before input. See section 2.1.30.

Added AVX512 VBMI2 (Additional Bit Manipulation), VNNI (Vector Neural
 Network), BITALG (Bit Algorithm), and GFNI (Galois Field New
 Instruction) instructions.

Added the STATIC directive for local symbols that should be renamed
 using global-symbol rules. See section 6.8.

Allow a symbol to be defined as EXTERN and then later overridden as
 GLOBAL or COMMON. Furthermore, a symbol declared EXTERN and then ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'nasm' package(s) on SUSE Linux Enterprise Module for Development Tools 15-SP1, SUSE Linux Enterprise Module for Development Tools 15-SP2.");

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

  if(!isnull(res = isrpmvuln(pkg:"nasm", rpm:"nasm~2.14.02~3.4.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nasm-debuginfo", rpm:"nasm-debuginfo~2.14.02~3.4.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nasm-debugsource", rpm:"nasm-debugsource~2.14.02~3.4.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"nasm", rpm:"nasm~2.14.02~3.4.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nasm-debuginfo", rpm:"nasm-debuginfo~2.14.02~3.4.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nasm-debugsource", rpm:"nasm-debugsource~2.14.02~3.4.1", rls:"SLES15.0SP2"))) {
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
