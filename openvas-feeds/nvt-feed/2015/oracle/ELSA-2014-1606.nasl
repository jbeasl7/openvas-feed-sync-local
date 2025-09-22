# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123289");
  script_cve_id("CVE-2012-1571", "CVE-2014-0237", "CVE-2014-0238", "CVE-2014-1943", "CVE-2014-2270", "CVE-2014-3479", "CVE-2014-3480");
  script_tag(name:"creation_date", value:"2015-10-06 11:01:48 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Oracle: Security Advisory (ELSA-2014-1606)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2014-1606");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2014-1606.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'file' package(s) announced via the ELSA-2014-1606 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[5.04-21]
- fix typographical error in changelog

[5.04-20]
- fix #1037279 - better patch for the bug from previous release

[5.04-19]
- fix #1037279 - display 'from' field on 32bit ppc core

[5.04-18]
- fix #664513 - trim white-spaces during ISO9660 detection

[5.04-17]
- fix CVE-2014-3479 (cdf_check_stream_offset boundary check)
- fix CVE-2014-3480 (cdf_count_chain insufficient boundary check)
- fix CVE-2014-0237 (cdf_unpack_summary_info() excessive looping DoS)
- fix CVE-2014-0238 (CDF property info parsing nelements infinite loop)
- fix CVE-2014-2270 (out-of-bounds access in search rules with offsets)
- fix CVE-2014-1943 (unrestricted recursion in handling of indirect type rules)
- fix CVE-2012-1571 (out of bounds read in CDF parser)

[5.04-16]
- fix #873997 - improve Minix detection pattern to fix false positives
- fix #884396 - improve PBM pattern to fix misdetection with x86 boot sector
- fix #980941 - improve Bio-Rad pattern to fix false positives
- fix #849621 - tweak strength of XML, Latex and Python patterns to execute
 them in the proper order
- fix #1067771 - detect qcow version 3 images
- fix #1064463 - treat RRDTool files as binary files");

  script_tag(name:"affected", value:"'file' package(s) on Oracle Linux 6.");

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

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"file", rpm:"file~5.04~21.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"file-devel", rpm:"file-devel~5.04~21.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"file-libs", rpm:"file-libs~5.04~21.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"file-static", rpm:"file-static~5.04~21.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-magic", rpm:"python-magic~5.04~21.el6", rls:"OracleLinux6"))) {
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
