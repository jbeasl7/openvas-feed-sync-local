# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123441");
  script_cve_id("CVE-2012-6151", "CVE-2014-2285");
  script_tag(name:"creation_date", value:"2015-10-06 11:03:52 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_name("Oracle: Security Advisory (ELSA-2014-0322)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2014-0322");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2014-0322.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'net-snmp' package(s) announced via the ELSA-2014-0322 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[5.3.2.2-22.0.2.el5_10.1]
- hrProcessorLoad returns incorrect values for CPUs greater than 100 (Jason Luan) [Orabug 17792842]
- snmptrapd: Fix crash due to access of freed memory (John Haxby) [orabug 14391194]
- suppress spurious asserts on 32bit [Greg Marsden]

[5.3.2.2-20.1]
- Fixed CVE-2012-6151: snmpd crashing when AgentX subagent disconnects in
 the middle of request processing (#1073224)
- Fixed CVE-2014-2285: snmptrapd crash when using a trap with empty community
 string (#1073224)");

  script_tag(name:"affected", value:"'net-snmp' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"net-snmp", rpm:"net-snmp~5.3.2.2~22.0.2.el5_10.1", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"net-snmp-devel", rpm:"net-snmp-devel~5.3.2.2~22.0.2.el5_10.1", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"net-snmp-libs", rpm:"net-snmp-libs~5.3.2.2~22.0.2.el5_10.1", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"net-snmp-perl", rpm:"net-snmp-perl~5.3.2.2~22.0.2.el5_10.1", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"net-snmp-utils", rpm:"net-snmp-utils~5.3.2.2~22.0.2.el5_10.1", rls:"OracleLinux5"))) {
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
