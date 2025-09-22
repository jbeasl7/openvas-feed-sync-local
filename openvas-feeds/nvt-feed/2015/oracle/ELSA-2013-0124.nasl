# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123759");
  script_cve_id("CVE-2012-2141");
  script_tag(name:"creation_date", value:"2015-10-06 11:08:09 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:N/A:P");

  script_name("Oracle: Security Advisory (ELSA-2013-0124)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2013-0124");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2013-0124.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'net-snmp' package(s) announced via the ELSA-2013-0124 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[5.3.2.2-20.0.2.el5]
- snmptrapd: Fix crash due to access of freed memory (John Haxby) [orabug 14391194]

[5.3.2.2-20.0.1.el5]
- suppress spurious asserts on 32bit [Greg Marsden]

[5.3.2.2-20]
- fixed error message when the address specified by clientaddr option
 is wrong or cannot be bound (#840861)

[5.3.2.2-19]
- fixed support for port numbers in 'clientaddr' configuration option
 (#840861, #845974)
- added support of cvfs filesystem hrStorageTable (#846391)
- removed various error log messages when IPv6 is disabled (#845155)
- removed various error log messages related to counte64 expansions
 (#846905)

[5.3.2.2-18]
- added support of ocfs2, tmpfs and reiserfs in hrStorageTable
 (#754652, #755958, #822061)
- updated documentation of '-c' option of snmptrapd (#760001)
- fixed endless loop after truncating 64bit int (#783892)
- fixed snmpd exiting shortly after startup due to incoming signal (#799699)
- fixed decoding of COUNTER64 values from AgentX (#803585)
- fixed engineID of outgoing traps if 'trapsess -e ' is used in
 snmpd.conf (#805689)
- fixed CVE-2012-2141, an array index error in the extension table (#815813)
- fixed snmpd showing 'failed to run mteTrigger query' when 'monitor'
 config option is used (#830042)
- added support for port numbers in 'clientaddr' configuration option
 (#828691)");

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

  if(!isnull(res = isrpmvuln(pkg:"net-snmp", rpm:"net-snmp~5.3.2.2~20.0.2.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"net-snmp-devel", rpm:"net-snmp-devel~5.3.2.2~20.0.2.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"net-snmp-libs", rpm:"net-snmp-libs~5.3.2.2~20.0.2.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"net-snmp-perl", rpm:"net-snmp-perl~5.3.2.2~20.0.2.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"net-snmp-utils", rpm:"net-snmp-utils~5.3.2.2~20.0.2.el5", rls:"OracleLinux5"))) {
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
