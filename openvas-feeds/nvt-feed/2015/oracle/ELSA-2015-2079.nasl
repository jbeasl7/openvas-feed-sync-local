# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122749");
  script_cve_id("CVE-2014-8484", "CVE-2014-8485", "CVE-2014-8501", "CVE-2014-8502", "CVE-2014-8503", "CVE-2014-8504", "CVE-2014-8737", "CVE-2014-8738");
  script_tag(name:"creation_date", value:"2015-11-24 08:17:24 +0000 (Tue, 24 Nov 2015)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Oracle: Security Advisory (ELSA-2015-2079)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux7");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-2079");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-2079.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'binutils' package(s) announced via the ELSA-2015-2079 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.23.52.0.1-55]
- Add missing delta to patch that fixes parsing corrupted archives.
 (#1162666)

[2.23.52.0.1-54]
- Import patch for PR 18270: Create AArch64 GOT entries for local symbols.
 (#1238783)

[2.23.52.0.1-51]
- Fix incorrectly generated binaries and DSOs on PPC platforms.
 (#1247126)

[2.23.52.0.1-50]
- Fix memory corruption parsing corrupt archives.
 (#1162666)

[2.23.52.0.1-49]
- Fix directory traversal vulnerability.
 (#1162655)

[2.23.52.0.1-48]
- Fix stack overflow in SREC parser.
 (#1162621)

[2.23.52.0.1-47]
- Fix stack overflow whilst parsing a corrupt iHex file.
 (#1162607)

[2.23.52.0.1-46]
- Fix out of bounds memory accesses when parsing corrupt PE binaries.
 (#1162594, #1162570)

[2.23.52.0.1-45]
- Change strings program to default to -a. Fix problems parsing
 files containing corrupt ELF group sections. (#1157276)

[2.23.52.0.1-44]
- Avoid reading beyond function boundary when disassembling.
 (#1060282)

- For binary output, we don't have an ELF bfd output so can't access
 elf_elfheader. (#1226864)

[2.23.52.0.1-43]
- Don't discard stap probe note sections on aarch64 (#1225091)

[2.23.52.0.1-42]
- Clamp maxpagesize at 1 (rather than 0) to avoid segfaults
 in the linker when passed a bogus max-page-size argument.
 (#1203449)

[2.23.52.0.1-41]
- Fixup bfd elf_link_add_object_symbols for ppc64 to prevent subsequent
 uninitialized accesses elsewhere. (#1172766)

[2.23.52.0.1-40]
- Minor testsuite adjustments for PPC changes in -38/-39.
 (#1183838)
 Fix md_assemble for PPC to handle arithmetic involving the TOC
 better. (#1183838)

[2.23.52.0.1-39]
- Fix ppc64: segv in libbfd (#1172766).

[2.23.52.0.1-38]
- Unconditionally apply ppc64le patches (#1183838).

[2.23.52.0.1-37]
- Andreas's backport of z13 and dependent fixes for s390,
 including tesetcase fix from Apr 27, 2015. (#1182153)

[2.23.52.0.1-35]
- Fixup testsuite for AArch64 (#1182111)
- Add support for @localentry for LE PPC64 (#1194164)

[2.23.52.0.1-34]
- Do not install windmc(1) man page (#850832)

[2.23.52.0.1-33]
- Don't replace R_390_TLS_LE{32,64} with R_390_TLS_TPOFF for PIE
 (#872148)
- Enable relro by default for arm and aarch64 (#1203449)
- Backport 3 RELRO improvements for ppc64/ppc64le from upstream
 (#1175624)

[2.23.52.0.1-31]
- Backport upstream RELRO fixes. (#1200138)");

  script_tag(name:"affected", value:"'binutils' package(s) on Oracle Linux 7.");

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

if(release == "OracleLinux7") {

  if(!isnull(res = isrpmvuln(pkg:"binutils", rpm:"binutils~2.23.52.0.1~55.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-devel", rpm:"binutils-devel~2.23.52.0.1~55.el7", rls:"OracleLinux7"))) {
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
