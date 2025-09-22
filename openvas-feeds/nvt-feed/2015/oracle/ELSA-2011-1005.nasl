# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122120");
  script_cve_id("CVE-2007-3852");
  script_tag(name:"creation_date", value:"2015-10-06 11:13:24 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Oracle: Security Advisory (ELSA-2011-1005)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2011-1005");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2011-1005.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sysstat' package(s) announced via the ELSA-2011-1005 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[7.0.2-11]
- Related: #716959
 fix cve-2007-3852 - sysstat insecure temporary file usage

[7.0.2-10]
- Resolves: #716959
 fix cve-2007-3852 - sysstat insecure temporary file usage

[7.0.2-9]
- Related: #622557
 sar interrupt count goes backward

[7.0.2-8]
- Resolves: #694767
 iostat doesn't report statistics for shares with long names
- Related: #703095
 iostat -n - values in output overflows - problem with long device names on
 i386

[7.0.2-7]
- Resolves: #706095
 iostat -n - values in output overflows

[7.0.2-6]
- Resolves: #696672
 cifsstat resource leak

[7.0.2-5]
- Resolves: #604637
 extraneous newline in iostat report for long device names
- Resolves: #630559
 'sar -P ALL -f xxxx' does not display activity information
- Resolves: #591530
 add cifsiostat tool
- Resolves: #598794
 Enable parametrization of sadc arguments
- Resolves: #675058
 iostat: bogus value appears when device is unmounted/mounted
- Resolves: #622557
 sar interrupt count goes backward

[7.0.2-4]
- Resolves: #454617
 Though function write() executed successful, sadc end with an error
- Resolves: #468340
 The output of sar -I ALL/XALL is wrong in ia64 machine of RHEL5
- Resolves: #517490
 The 'sar -d ' command outputs invalid data
- Resolves: #578929
 March sar data was appended to February data
- Resolves: #579409
 The sysstat's programs such as mpstat shows one extra cpu
- Resolves: #484439
 iostat -n enhancement not report NFS client stats correctly");

  script_tag(name:"affected", value:"'sysstat' package(s) on Oracle Linux 5.");

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

if(release == "OracleLinux5") {

  if(!isnull(res = isrpmvuln(pkg:"sysstat", rpm:"sysstat~7.0.2~11.el5", rls:"OracleLinux5"))) {
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
