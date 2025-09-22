# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122757");
  script_cve_id("CVE-2014-3565");
  script_tag(name:"creation_date", value:"2015-11-24 08:17:30 +0000 (Tue, 24 Nov 2015)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Oracle: Security Advisory (ELSA-2015-2345)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux7");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-2345");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-2345.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'net-snmp' package(s) announced via the ELSA-2015-2345 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1:5.7.2-24]
- Fixed lmSensorsTable not reporting sensors with duplicate names
 (#1252053)
- Fixed close() overhead of extend commands (#1252048)
- Fixed out-of-bounds write in python code (#1252034)

[1:5.7.2-23]
- Fixed parsing of invalid variables in incoming packets (#1248414)
- Fixed HOST-RESOURCES-MIB::hrFSAccess flag when read-only filesystem
 becomes writable (#1241897)

[1:5.7.2-22]
- Fixed IP-MIB::ipSystemStatsInOctets and similar counters for IPv4
 (#1235697)

[1:5.7.2-21]
- Fixed crash on reloading 'exec' configuration options (#1228893)
- Fixed CVE-2014-3565, snmptrapd died when parsing certain traps (#1209361)
- Fixed storageUseNFS functionality in hrStorageTable (#1193006)
- Fixed forwarding of traps with RequestID=0 in snmptrapd (#1192511)
- Fixed hrStorageTable to contain 31 bits integers (#1192221)
- Fixed 'clientaddr' option for UDPv6 client messages (#1190679)
- Fixed log level of SMUX messages (#1189393)
- Fixed UDP-MIB::udpTable index on big-endian platforms (#1184433)
- Fixed client utilities reporting 'read_config_store open failure on
 /var/lib/net-snmp/snmpapp.conf' (#1151310)
- Fixed snmpd crash when failed to parse SMUX message headers (#1140236)
- Added 'diskio' option to snmpd.conf, it's possible to monitor only
 selected devices in diskIOTable (#1092308)");

  script_tag(name:"affected", value:"'net-snmp' package(s) on Oracle Linux 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"net-snmp", rpm:"net-snmp~5.7.2~24.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"net-snmp-agent-libs", rpm:"net-snmp-agent-libs~5.7.2~24.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"net-snmp-devel", rpm:"net-snmp-devel~5.7.2~24.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"net-snmp-gui", rpm:"net-snmp-gui~5.7.2~24.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"net-snmp-libs", rpm:"net-snmp-libs~5.7.2~24.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"net-snmp-perl", rpm:"net-snmp-perl~5.7.2~24.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"net-snmp-python", rpm:"net-snmp-python~5.7.2~24.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"net-snmp-sysvinit", rpm:"net-snmp-sysvinit~5.7.2~24.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"net-snmp-utils", rpm:"net-snmp-utils~5.7.2~24.el7", rls:"OracleLinux7"))) {
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
