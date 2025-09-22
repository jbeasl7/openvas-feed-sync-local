# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64458");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-07-29 19:28:37 +0200 (Wed, 29 Jul 2009)");
  script_cve_id("CVE-2009-1892");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Mandrake Security Advisory MDVSA-2009:154 (dhcp)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/rpms", re:"ssh/login/release=MNDK_(2008\.1|2009\.0|2009\.1|3\.0|4\.0|2\.0)");
  script_tag(name:"insight", value:"A vulnerability has been found and corrected in ISC DHCP:

ISC DHCP Server is vulnerable to a denial of service, caused by the
improper handling of DHCP requests. If the host definitions are mixed
using dhcp-client-identifier and hardware ethernet, a remote attacker
could send specially-crafted DHCP requests to cause the server to
stop responding (CVE-2009-1892).

This update provides fixes for this vulnerability.

Affected: 2008.1, 2009.0, 2009.1, Corporate 3.0, Corporate 4.0,
          Multi Network Firewall 2.0");
  script_tag(name:"solution", value:"To upgrade automatically use MandrakeUpdate or urpmi. The verification
of md5 checksums and GPG signatures is performed automatically for you.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:154");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/51717");
  script_tag(name:"summary", value:"The remote host is missing an update to dhcp
announced via advisory MDVSA-2009:154.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"dhcp-client", rpm:"dhcp-client~3.0.7~0.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dhcp-common", rpm:"dhcp-common~3.0.7~0.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dhcp-devel", rpm:"dhcp-devel~3.0.7~0.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dhcp-doc", rpm:"dhcp-doc~3.0.7~0.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dhcp-relay", rpm:"dhcp-relay~3.0.7~0.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dhcp-server", rpm:"dhcp-server~3.0.7~0.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dhcp-client", rpm:"dhcp-client~3.0.7~1.4mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dhcp-common", rpm:"dhcp-common~3.0.7~1.4mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dhcp-devel", rpm:"dhcp-devel~3.0.7~1.4mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dhcp-doc", rpm:"dhcp-doc~3.0.7~1.4mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dhcp-relay", rpm:"dhcp-relay~3.0.7~1.4mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dhcp-server", rpm:"dhcp-server~3.0.7~1.4mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dhcp-client", rpm:"dhcp-client~4.1.0~5.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dhcp-common", rpm:"dhcp-common~4.1.0~5.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dhcp-devel", rpm:"dhcp-devel~4.1.0~5.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dhcp-doc", rpm:"dhcp-doc~4.1.0~5.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dhcp-relay", rpm:"dhcp-relay~4.1.0~5.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dhcp-server", rpm:"dhcp-server~4.1.0~5.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dhcp-client", rpm:"dhcp-client~3.0.7~0.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dhcp-common", rpm:"dhcp-common~3.0.7~0.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dhcp-devel", rpm:"dhcp-devel~3.0.7~0.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dhcp-relay", rpm:"dhcp-relay~3.0.7~0.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dhcp-server", rpm:"dhcp-server~3.0.7~0.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dhcp-client", rpm:"dhcp-client~3.0.7~0.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dhcp-common", rpm:"dhcp-common~3.0.7~0.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dhcp-devel", rpm:"dhcp-devel~3.0.7~0.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dhcp-relay", rpm:"dhcp-relay~3.0.7~0.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dhcp-server", rpm:"dhcp-server~3.0.7~0.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dhcp-client", rpm:"dhcp-client~3.0.7~0.2.C30mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dhcp-common", rpm:"dhcp-common~3.0.7~0.2.C30mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dhcp-devel", rpm:"dhcp-devel~3.0.7~0.2.C30mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dhcp-relay", rpm:"dhcp-relay~3.0.7~0.2.C30mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dhcp-server", rpm:"dhcp-server~3.0.7~0.2.C30mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
