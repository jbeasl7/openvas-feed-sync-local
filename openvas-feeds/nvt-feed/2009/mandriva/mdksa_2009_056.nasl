# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63451");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-03-02 19:11:09 +0100 (Mon, 02 Mar 2009)");
  script_cve_id("CVE-2008-6123");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Mandrake Security Advisory MDVSA-2009:056 (net-snmp)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/rpms", re:"ssh/login/release=MNDK_2009\.0");
  script_tag(name:"insight", value:"A vulnerability has been identified and corrected in net-snmp:

The netsnmp_udp_fmtaddr function (snmplib/snmpUDPDomain.c) in
net-snmp 5.0.9 through 5.4.2, when using TCP wrappers for client
authorization, does not properly parse hosts.allow rules, which
allows remote attackers to bypass intended access restrictions
and execute SNMP queries, related to source/destination IP address
confusion. (CVE-2008-6123)

The updated packages have been patched to prevent this.

Affected: 2009.0");
  script_tag(name:"solution", value:"To upgrade automatically use MandrakeUpdate or urpmi. The verification
of md5 checksums and GPG signatures is performed automatically for you.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:056");
  script_tag(name:"summary", value:"The remote host is missing an update to net-snmp
announced via advisory MDVSA-2009:056.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"libnet-snmp15", rpm:"libnet-snmp15~5.4.2~2.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libnet-snmp-devel", rpm:"libnet-snmp-devel~5.4.2~2.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libnet-snmp-static-devel", rpm:"libnet-snmp-static-devel~5.4.2~2.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"net-snmp", rpm:"net-snmp~5.4.2~2.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"net-snmp-mibs", rpm:"net-snmp-mibs~5.4.2~2.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"net-snmp-tkmib", rpm:"net-snmp-tkmib~5.4.2~2.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"net-snmp-trapd", rpm:"net-snmp-trapd~5.4.2~2.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"net-snmp-utils", rpm:"net-snmp-utils~5.4.2~2.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-NetSNMP", rpm:"perl-NetSNMP~5.4.2~2.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64net-snmp15", rpm:"lib64net-snmp15~5.4.2~2.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64net-snmp-devel", rpm:"lib64net-snmp-devel~5.4.2~2.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64net-snmp-static-devel", rpm:"lib64net-snmp-static-devel~5.4.2~2.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
