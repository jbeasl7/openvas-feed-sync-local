# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122739");
  script_cve_id("CVE-2014-0207", "CVE-2014-0237", "CVE-2014-0238", "CVE-2014-3478", "CVE-2014-3479", "CVE-2014-3480", "CVE-2014-3487", "CVE-2014-3538", "CVE-2014-3587", "CVE-2014-3710", "CVE-2014-8116", "CVE-2014-8117", "CVE-2014-9652", "CVE-2014-9653");
  script_tag(name:"creation_date", value:"2015-11-24 08:17:17 +0000 (Tue, 24 Nov 2015)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Oracle: Security Advisory (ELSA-2015-2155)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux7");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-2155");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-2155.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'file' package(s) announced via the ELSA-2015-2155 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[5.11-31]
- fix #1255396 - Make the build ID output consistent with other tools

[5.11-30]
- fix CVE-2014-8116 - bump the acceptable ELF program headers count to 2048

[5.11-29]
- fix #839229 - fix detection of version of XML files

[5.11-28]
- fix #839229 - fix detection of version of XML files

[5.11-27]
- fix CVE-2014-0207 - cdf_read_short_sector insufficient boundary check
- fix CVE-2014-0237 - cdf_unpack_summary_info() excessive looping DoS
- fix CVE-2014-0238 - CDF property info parsing nelements infinite loop
- fix CVE-2014-3478 - mconvert incorrect handling of truncated pascal string
- fix CVE-2014-3479 - fix extensive backtracking in regular expression
- fix CVE-2014-3480 - cdf_count_chain insufficient boundary check
- fix CVE-2014-3487 - cdf_read_property_info insufficient boundary check
- fix CVE-2014-3538 - unrestricted regular expression matching
- fix CVE-2014-3587 - fix cdf_read_property_info
- fix CVE-2014-3710 - out-of-bounds read in elf note headers
- fix CVE-2014-8116 - multiple denial of service issues (resource consumption)
- fix CVE-2014-8117 - denial of service issue (resource consumption)
- fix CVE-2014-9652 - out of bounds read in mconvert()
- fix CVE-2014-9653 - malformed elf file causes access to uninitialized memory

[5.11-26]
- fix #1080452 - remove .orig files from magic directory

[5.11-25]
- fix #1224667, #1224668 - show additional info for Linux swap files

[5.11-24]
- fix #1064268 - fix stray return -1

[5.11-23]
- fix #1094648 - improve Minix detection pattern to fix false positives
- fix #1161912 - trim white-spaces during ISO9660 detection
- fix #1157850 - fix detection of ppc64le ELF binaries
- fix #1161911 - display 'from' field on 32bit ppc core
- fix #1064167 - revert MAXMIME patch
- fix #1064268 - detect Dwarf debuginfo as 'not stripped'
- fix #1082689 - fix invalid read when matched pattern is the last one tried
- fix #1080362 - remove deadcode and OFFSET_OOB redefinition

[5.11-22]
- fix #1067688 - add support for aarch64 ELF binaries");

  script_tag(name:"affected", value:"'file' package(s) on Oracle Linux 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"file", rpm:"file~5.11~31.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"file-devel", rpm:"file-devel~5.11~31.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"file-libs", rpm:"file-libs~5.11~31.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"file-static", rpm:"file-static~5.11~31.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-magic", rpm:"python-magic~5.11~31.el7", rls:"OracleLinux7"))) {
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
