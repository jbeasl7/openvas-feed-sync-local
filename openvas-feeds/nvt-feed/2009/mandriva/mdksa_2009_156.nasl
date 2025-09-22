# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64456");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-07-29 19:28:37 +0200 (Wed, 29 Jul 2009)");
  script_cve_id("CVE-2008-4309", "CVE-2009-1887");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Mandrake Security Advisory MDVSA-2009:156 (net-snmp)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/rpms", re:"ssh/login/release=MNDK_(3\.0|2\.0)");
  script_tag(name:"insight", value:"A vulnerability has been found and corrected in net-snmp:

agent/snmp_agent.c in snmpd in net-snmp 5.0.9 in Red Hat Enterprise
Linux (RHEL) 3 allows remote attackers to cause a denial of service
(daemon crash) via a crafted SNMP GETBULK request that triggers a
divide-by-zero error.  NOTE: this vulnerability exists because of an
incorrect fix for CVE-2008-4309 (CVE-2009-1887).

This update provides fixes for this vulnerability.

Affected: Corporate 3.0, Multi Network Firewall 2.0");
  script_tag(name:"solution", value:"To upgrade automatically use MandrakeUpdate or urpmi. The verification
of md5 checksums and GPG signatures is performed automatically for you.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:156");
  script_tag(name:"summary", value:"The remote host is missing an update to net-snmp
announced via advisory MDVSA-2009:156.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"libnet-snmp5", rpm:"libnet-snmp5~5.1~7.5.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libnet-snmp5-devel", rpm:"libnet-snmp5-devel~5.1~7.5.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libnet-snmp5-static-devel", rpm:"libnet-snmp5-static-devel~5.1~7.5.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"net-snmp", rpm:"net-snmp~5.1~7.5.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"net-snmp-mibs", rpm:"net-snmp-mibs~5.1~7.5.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"net-snmp-trapd", rpm:"net-snmp-trapd~5.1~7.5.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"net-snmp-utils", rpm:"net-snmp-utils~5.1~7.5.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64net-snmp5", rpm:"lib64net-snmp5~5.1~7.5.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64net-snmp5-devel", rpm:"lib64net-snmp5-devel~5.1~7.5.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64net-snmp5-static-devel", rpm:"lib64net-snmp5-static-devel~5.1~7.5.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libnet-snmp5", rpm:"libnet-snmp5~5.1~7.5.C30mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libnet-snmp5-devel", rpm:"libnet-snmp5-devel~5.1~7.5.C30mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libnet-snmp5-static-devel", rpm:"libnet-snmp5-static-devel~5.1~7.5.C30mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"net-snmp", rpm:"net-snmp~5.1~7.5.C30mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"net-snmp-mibs", rpm:"net-snmp-mibs~5.1~7.5.C30mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"net-snmp-trapd", rpm:"net-snmp-trapd~5.1~7.5.C30mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"net-snmp-utils", rpm:"net-snmp-utils~5.1~7.5.C30mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
