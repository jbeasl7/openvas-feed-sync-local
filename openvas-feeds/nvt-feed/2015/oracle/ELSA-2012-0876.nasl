# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123888");
  script_cve_id("CVE-2012-2141");
  script_tag(name:"creation_date", value:"2015-10-06 11:09:53 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:N/A:P");

  script_name("Oracle: Security Advisory (ELSA-2012-0876)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2012-0876");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2012-0876.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'net-snmp' package(s) announced via the ELSA-2012-0876 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1:5.5-41]
- moved /var/lib/net-snmp from net-snmp to net-snmp-libs package
 (#822480)

[1:5.5-40]
- fixed CVE-2012-2141 (#820100)

[1:5.5-39]
- fixed proxying of out-of-tree GETNEXT requests (#799291)

[1:5.5-38]
- fixed snmpd crashing with many AgentX subagent (#749227)
- fixed SNMPv2-MIB::sysObjectID value when sysObjectID config file
 option with long OID was used (#786931)
- fixed value of BRIDGE-MIB::dot1dBasePortIfIndex.1 (#740172)
- fixed parsing of proxy snmpd.conf option not to enable
 verbose logging by default (#746903)
- added new realStorageUnits config file option to support
 disks > 16 TB in hrStorageTable (#741789)
- added vxfs, reiserfs and ocfs2 filesystem support to hrStorageTable
 (#746903)
- fixed snmpd sigsegv when embedded perl script registers one handler
 twice (#748907)
- fixed setting of SNMP-TARGET-MIB::snmpTargetAddrRowStatus via
 SNMP-SET request on 64-bit platforms (#754275)
- fixed crash when /var/lib/net-snmp/mib_indexes/ files have wrong
 SELinux context (#754971)
- fixed memory leak when agentx subagent disconnects in the middle
 of request processing (#736580)
- fixed slow (re-)loads of TCP-MIB::tcpConnectionTable (#789909)
- removed 'error finding row index in _ifXTable_container_row_restore'
 error message (#788954)");

  script_tag(name:"affected", value:"'net-snmp' package(s) on Oracle Linux 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"net-snmp", rpm:"net-snmp~5.5~41.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"net-snmp-devel", rpm:"net-snmp-devel~5.5~41.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"net-snmp-libs", rpm:"net-snmp-libs~5.5~41.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"net-snmp-perl", rpm:"net-snmp-perl~5.5~41.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"net-snmp-python", rpm:"net-snmp-python~5.5~41.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"net-snmp-utils", rpm:"net-snmp-utils~5.5~41.el6", rls:"OracleLinux6"))) {
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
